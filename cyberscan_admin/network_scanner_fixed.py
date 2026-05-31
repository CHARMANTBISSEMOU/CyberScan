"""
CyberScan Network Scanner - Version Corrigée
Module de surveillance réseau complet avec scan automatique et identification d'appareils.
Corrections des problèmes de détection réseau et de scan.
"""

import asyncio
import threading
import time
import socket
import subprocess
import platform
import ipaddress
import sqlite3
import logging
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import ctypes
from ctypes import wintypes

# Configuration optimisée
SCAN_INTERVAL_QUICK = 30  # secondes - scan rapide non-intrusif
SCAN_INTERVAL_FULL = 600  # secondes - scan complet des ports
MAX_THREADS = 80  # threads max pour scanner rapidement toute la plage du masque
PORT_TIMEOUT = 0.4  # timeout court pour accélérer le scan réseau
HISTORY_RETENTION_DAYS = 30

# Base de données OUI pour les constructeurs (version simplifiée)
OUI_DATABASE = {
    '00:1B:44': 'Microsoft Corporation',
    '00:50:56': 'VMware, Inc.',
    '08:00:27': 'Oracle Corporation',
    '00:0C:29': 'VMware, Inc.',
    '00:1C:42': 'Parallels, Inc.',
    '00:17:F2': 'Apple, Inc.',
    '28:CF:E9': 'Apple, Inc.',
    'A4:C3:61': 'Apple, Inc.',
    '40:A6:D9': 'Apple, Inc.',
    '98:01:A7': 'Apple, Inc.',
    'B4:2E:99': 'Apple, Inc.',
    'D0:03:4B': 'Apple, Inc.',
    'F0:18:98': 'Apple, Inc.',
    '28:E7:CF': 'Apple, Inc.',
    'AC:DE:48': 'Private',
    '00:00:00': 'Unknown',
}

class NetworkScannerFixed:
    def __init__(self, db_path="cyberscan.db"):
        self.db_path = db_path
        self.running = False
        self.scan_thread = None
        self.full_scan_thread = None
        self.network_ranges = []
        self.discovered_devices = {}
        self.new_devices_callback = None
        self.logger = logging.getLogger(__name__)
        
        # Initialiser la base de données
        self._init_database()
        
        # Détecter les réseaux locaux
        self._detect_local_networks()
    
    def _init_database(self):
        """Crée les tables pour le scan réseau."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des appareils réseau
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    manufacturer TEXT,
                    device_type TEXT,
                    os_guess TEXT,
                    open_ports TEXT,  -- JSON array
                    services TEXT,     -- JSON array
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'unknown',
                    risk_score INTEGER DEFAULT 0,
                    is_blacklisted BOOLEAN DEFAULT 0
                )
            ''')
            
            # Table des événements réseau
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT NOT NULL,
                    event_type TEXT NOT NULL,  -- 'new_device', 'device_offline', 'port_opened', etc.
                    event_data TEXT,  -- JSON
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_ip) REFERENCES network_devices(ip_address)
                )
            ''')
            
            # Index pour optimiser les requêtes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_ip ON network_devices(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON network_devices(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_device_ip ON network_events(device_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON network_events(timestamp)')
            
            conn.commit()
        self.logger.info("Base de données réseau initialisée")
    
    def _detect_local_networks(self):
        """Détecte automatiquement les plages réseau locales (version corrigée)."""
        try:
            # Obtenir toutes les interfaces réseau
            interfaces = psutil.net_if_addrs()
            
            # Prioriser les interfaces actives avec une connexion
            active_interfaces = []
            
            for interface_name, addresses in interfaces.items():
                for address in addresses:
                    if address.family == socket.AF_INET:  # IPv4
                        ip = address.address
                        netmask = address.netmask
                        
                        # Ignorer localhost et liens locaux (APIPA)
                        if ip.startswith('127.') or ip.startswith('169.254.'):
                            continue
                        
                        # Ignorer les interfaces virtuelles si possible
                        if any(keyword in interface_name.lower() for keyword in ['virtual', 'vmware', 'vbox', 'docker', 'vethernet', 'hyper-v', 'default switch', 'wsl']):
                            continue
                        
                        # Vérifier si l'interface est active
                        try:
                            stats = psutil.net_if_stats()[interface_name]
                            if not stats.isup:
                                continue
                        except:
                            continue
                        
                        # Calculer le réseau
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            
                            # Ne garder que les réseaux privés et de taille raisonnable
                            if network.is_private and network.prefixlen <= 24:  # /24 ou plus grand
                                active_interfaces.append((network, interface_name, ip))
                        except:
                            continue
            
            # Trier par priorité (réseaux plus petits en premier)
            active_interfaces.sort(key=lambda x: x[0].prefixlen, reverse=True)
            
            # Ajouter les réseaux détectés
            for network, interface_name, ip in active_interfaces:
                self.network_ranges.append(str(network))
                self.logger.info(f"Réseau détecté: {network} (interface: {interface_name}, IP: {ip})")
            
            if not self.network_ranges:
                # Fallback : réseau commun par défaut
                self.network_ranges = ["192.168.1.0/24"]
                self.logger.warning("Aucun réseau détecté, utilisation du réseau par défaut: 192.168.1.0/24")
                
        except Exception as e:
            self.logger.error(f"Erreur détection réseau: {e}")
            self.network_ranges = ["192.168.1.0/24"]
    
    def _get_manufacturer_from_mac(self, mac_address):
        """Retourne le constructeur depuis l'adresse MAC."""
        if not mac_address:
            return "Unknown"
        
        # Extraire les 3 premiers octets (OUI)
        oui = mac_address.upper().replace('-', ':')[:8]
        return OUI_DATABASE.get(oui, "Unknown")
    
    def _ping_host(self, ip):
        """Test de connectivité ICMP (version améliorée)."""
        try:
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', '-w', '1000', ip]  # Augmenté à 1000ms
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, timeout=3, 
                                  creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0)
            return result.returncode == 0
        except:
            return False
    
    def _get_mac_address(self, ip):
        """Obtient l'adresse MAC via ARP (version améliorée)."""
        try:
            if platform.system().lower() == "windows":
                # Utiliser la table ARP Windows
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=10,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:
                                    return part.replace('-', ':').upper()
            else:
                # Linux/macOS
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line and 'ether' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'ether' and i + 1 < len(parts):
                                    return parts[i + 1].upper()
        except:
            pass
        return None
    
    def _get_hostname(self, ip):
        """Résolution DNS/reverse lookup (version améliorée)."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _scan_port(self, ip, port):
        """Scan d'un port spécifique (version améliorée)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def _scan_ports_quick(self, ip, common_ports=None):
        """Scan rapide des ports communs (version optimisée)."""
        if common_ports is None:
            common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        open_ports = []
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:  # Réduit à 10
                futures = {executor.submit(self._scan_port, ip, port): port for port in common_ports}
                for future in as_completed(futures):
                    port = future.result()
                    if port:
                        open_ports.append(port)
        except Exception as e:
            self.logger.warning(f"Erreur scan ports {ip}: {e}")
        
        return open_ports
    
    def _identify_device_type(self, ip, open_ports, hostname):
        """Identifie le type d'appareil selon les ports et hostname."""
        # Logique d'identification simple
        if hostname:
            hostname_lower = hostname.lower()
            if any(keyword in hostname_lower for keyword in ['printer', 'imprimante', 'hp', 'canon', 'epson']):
                return 'printer'
            elif any(keyword in hostname_lower for keyword in ['router', 'gateway', 'box', 'livebox']):
                return 'router'
            elif any(keyword in hostname_lower for keyword in ['server', 'srv', 'dc']):
                return 'server'
            elif any(keyword in hostname_lower for keyword in ['phone', 'mobile', 'android', 'iphone']):
                return 'mobile'
        
        # Identification par ports
        if 22 in open_ports or 3389 in open_ports:
            return 'computer'
        elif 80 in open_ports or 443 in open_ports:
            if len(open_ports) > 5:
                return 'server'
            else:
                return 'iot_device'
        elif 21 in open_ports or 23 in open_ports:
            return 'network_device'
        
        return 'unknown'
    
    def _calculate_risk_score(self, device):
        """Calcule un score de risque pour l'appareil."""
        score = 0
        
        # Ports ouverts dangereux
        dangerous_ports = [23, 135, 139, 445, 1433, 3389]
        open_ports = json.loads(device.get('open_ports', '[]'))
        for port in dangerous_ports:
            if port in open_ports:
                score += 2
        
        # Appareil inconnu
        if device.get('device_type') == 'unknown':
            score += 3
        
        # Pas de hostname
        if not device.get('hostname'):
            score += 1
        
        return min(score, 10)  # Score max 10
    
    def _scan_single_ip(self, ip):
        """Scan complet d'une adresse IP (version améliorée)."""
        try:
            # Test de connectivité
            if not self._ping_host(ip):
                return None
            
            # Informations de base
            mac = self._get_mac_address(ip)
            hostname = self._get_hostname(ip)
            manufacturer = self._get_manufacturer_from_mac(mac)
            
            # Scan rapide des ports communs
            open_ports = self._scan_ports_quick(ip)
            
            # Identification
            device_type = self._identify_device_type(ip, open_ports, hostname)
            
            device = {
                'ip_address': ip,
                'mac_address': mac,
                'hostname': hostname,
                'manufacturer': manufacturer,
                'device_type': device_type,
                'os_guess': None,  # Sera ajouté plus tard
                'open_ports': json.dumps(open_ports),
                'services': json.dumps([]),  # Sera rempli plus tard
                'status': 'online'
            }
            
            return device
            
        except Exception as e:
            self.logger.warning(f"Erreur scan {ip}: {e}")
            return None
    
    def _quick_scan_network(self):
        """Scan rapide du réseau (version corrigée)."""
        self.logger.info("Début scan rapide réseau...")
        
        all_devices = {}
        new_devices = []
        
        for network_range in self.network_ranges:
            try:
                network = ipaddress.IPv4Network(network_range)
                ips = [str(ip) for ip in network.hosts()]
                
                self.logger.info(f"Scan de {len(ips)} adresses IP dans {network_range}")
                
                # Scan parallèle avec moins de threads
                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    futures = {executor.submit(self._scan_single_ip, ip): ip for ip in ips}
                    
                    completed = 0
                    for future in as_completed(futures):
                        device = future.result()
                        completed += 1
                        
                        if device:
                            all_devices[device['ip_address']] = device
                            
                            # Vérifier si c'est un nouvel appareil
                            if device['ip_address'] not in self.discovered_devices:
                                new_devices.append(device)
                                self._log_network_event(device['ip_address'], 'new_device', device)
                        
                        # Progression
                        if completed % 20 == 0:
                            self.logger.info(f"Progression: {completed}/{len(ips)} IPs scannées")
                
            except Exception as e:
                self.logger.error(f"Erreur scan réseau {network_range}: {e}")
        
        # Mettre à jour les appareils existants
        self._update_devices_in_database(all_devices)
        
        # Notifier les nouveaux appareils
        if new_devices and self.new_devices_callback:
            self.new_devices_callback(new_devices)
        
        self.discovered_devices = all_devices
        self.logger.info(f"Scan rapide terminé: {len(all_devices)} appareils trouvés, {len(new_devices)} nouveaux")
    
    def _update_devices_in_database(self, devices):
        """Met à jour les appareils dans la base de données."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for ip, device in devices.items():
                    # Vérifier si l'appareil existe déjà
                    cursor.execute('SELECT id FROM network_devices WHERE ip_address = ?', (ip,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Mettre à jour l'appareil existant
                        cursor.execute('''
                            UPDATE network_devices SET 
                                mac_address = ?, hostname = ?, manufacturer = ?, 
                                device_type = ?, open_ports = ?, last_seen = CURRENT_TIMESTAMP,
                                status = 'online'
                            WHERE ip_address = ?
                        ''', (device['mac_address'], device['hostname'], 
                              device['manufacturer'], device['device_type'], 
                              device['open_ports'], ip))
                    else:
                        # Insérer le nouvel appareil
                        cursor.execute('''
                            INSERT INTO network_devices 
                            (ip_address, mac_address, hostname, manufacturer, 
                             device_type, open_ports, status)
                            VALUES (?, ?, ?, ?, ?, ?, 'online')
                        ''', (device['ip_address'], device['mac_address'], 
                              device['hostname'], device['manufacturer'], 
                              device['device_type'], device['open_ports']))
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Erreur mise à jour base de données: {e}")
    
    def _log_network_event(self, device_ip, event_type, event_data):
        """Enregistre un événement réseau."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO network_events (device_ip, event_type, event_data)
                    VALUES (?, ?, ?)
                ''', (device_ip, event_type, json.dumps(event_data)))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Erreur enregistrement événement: {e}")
    
    def start_monitoring(self, callback=None):
        """Démarre la surveillance réseau."""
        if self.running:
            self.logger.warning("La surveillance est déjà en cours")
            return
        
        self.running = True
        self.new_devices_callback = callback
        
        # Démarrer le thread de scan rapide
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        self.logger.info("Surveillance réseau démarrée")
    
    def stop_monitoring(self):
        """Arrête la surveillance réseau."""
        self.running = False
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=5)
        
        if self.full_scan_thread and self.full_scan_thread.is_alive():
            self.full_scan_thread.join(timeout=5)
        
        self.logger.info("Surveillance réseau arrêtée")
    
    def _scan_loop(self):
        """Boucle principale de scan."""
        while self.running:
            try:
                self._quick_scan_network()
                time.sleep(SCAN_INTERVAL_QUICK)
            except Exception as e:
                self.logger.error(f"Erreur dans la boucle de scan: {e}")
                time.sleep(5)  # Pause en cas d'erreur
    
    def get_discovered_devices(self):
        """Retourne les appareils découverts."""
        return list(self.discovered_devices.values())
    
    def get_devices_from_database(self, limit=100):
        """Récupère les appareils depuis la base de données."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM network_devices 
                    ORDER BY last_seen DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                devices = []
                
                for row in cursor.fetchall():
                    device = dict(zip(columns, row))
                    devices.append(device)
                
                return devices
        except Exception as e:
            self.logger.error(f"Erreur récupération appareils: {e}")
            return []
    
    def manual_scan(self, network_range=None):
        """Lance un scan manuel."""
        if network_range:
            old_ranges = self.network_ranges.copy()
            self.network_ranges = [network_range]
        
        try:
            self._quick_scan_network()
            result = list(self.discovered_devices.values())
        finally:
            if network_range:
                self.network_ranges = old_ranges
        
        return result
    
    def get_recent_events(self, limit=50):
        """Récupère les événements réseau récents."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM network_events 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                events = []
                
                for row in cursor.fetchall():
                    event = dict(zip(columns, row))
                    events.append(event)
                
                return events
        except Exception as e:
            self.logger.error(f"Erreur récupération événements: {e}")
            return []

# Test du scanner corrigé
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    scanner = NetworkScannerFixed()
    
    print("=== TEST DU SCANNER RÉSEAU CORRIGÉ ===")
    print(f"Réseaux détectés: {scanner.network_ranges}")
    
    # Scan manuel pour test
    print("\nLancement d'un scan manuel...")
    devices = scanner.manual_scan()
    
    print(f"\nAppareils découverts: {len(devices)}")
    for device in devices:
        print(f"  📱 {device['ip_address']} - {device['hostname'] or 'Unknown'} ({device['device_type']})")
        if device['mac_address']:
            print(f"     MAC: {device['mac_address']} - {device['manufacturer']}")
        ports = json.loads(device['open_ports'])
        if ports:
            print(f"     Ports ouverts: {ports}")
