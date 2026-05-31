"""
CyberScan Network Scanner
Module de surveillance réseau complet avec scan automatique et identification d'appareils.
Fonctionne en local sans dépendance externe.
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

# Configuration
SCAN_INTERVAL_QUICK = 20  # secondes - scan rapide non-intrusif
SCAN_INTERVAL_FULL = 300  # secondes - scan complet des ports
MAX_THREADS = 50  # threads max pour scan parallèle
PORT_TIMEOUT = 0.5  # timeout par port (secondes)
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

class NetworkScanner:
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
            
            # Index pour performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_ip ON network_devices(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_status ON network_devices(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_timestamp ON network_events(timestamp)')
            
            conn.commit()
            self.logger.info("Base de données réseau initialisée")
    
    def _detect_local_networks(self):
        """Détecte automatiquement les plages réseau locales."""
        try:
            # Obtenir toutes les interfaces réseau
            interfaces = psutil.net_if_addrs()
            
            for interface_name, addresses in interfaces.items():
                for address in addresses:
                    if address.family == socket.AF_INET:  # IPv4
                        ip = address.address
                        netmask = address.netmask
                        
                        # Ignorer localhost et liens locaux
                        if ip.startswith('127.') or ip.startswith('169.254.'):
                            continue
                        
                        # Calculer le réseau
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            
                            # Ne garder que les réseaux privés
                            if network.is_private:
                                self.network_ranges.append(str(network))
                                self.logger.info(f"Réseau détecté: {network} (interface: {interface_name})")
                        except:
                            continue
            
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
        """Test de connectivité ICMP."""
        try:
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '0.5', ip]
            
            result = subprocess.run(cmd, capture_output=True, timeout=2, 
                                  creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0)
            return result.returncode == 0
        except:
            return False
    
    def _get_mac_address(self, ip):
        """Obtient l'adresse MAC via ARP."""
        try:
            if platform.system().lower() == "windows":
                # Utiliser la table ARP Windows
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5,
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
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
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
        """Résolution DNS/reverse lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _scan_port(self, ip, port):
        """Scan d'un port spécifique."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def _scan_ports_quick(self, ip, common_ports=None):
        """Scan rapide des ports communs."""
        if common_ports is None:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        open_ports = []
        try:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self._scan_port, ip, port): port for port in common_ports}
                for future in as_completed(futures):
                    port = future.result()
                    if port:
                        open_ports.append(port)
        except Exception as e:
            self.logger.warning(f"Erreur scan ports {ip}: {e}")
        
        return open_ports
    
    def _scan_ports_full(self, ip):
        """Scan complet de tous les ports (1-65535)."""
        open_ports = []
        try:
            # Scan par blocs de 100 ports pour éviter la surcharge
            port_ranges = [(start, min(start + 99, 65535)) for start in range(1, 65536, 100)]
            
            for start, end in port_ranges:
                ports = list(range(start, end + 1))
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = {executor.submit(self._scan_port, ip, port): port for port in ports}
                    for future in as_completed(futures):
                        port = future.result()
                        if port:
                            open_ports.append(port)
                
                # Petite pause entre les blocs
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.warning(f"Erreur scan complet ports {ip}: {e}")
        
        return sorted(open_ports)
    
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
        """Scan complet d'une adresse IP."""
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
        """Scan rapide du réseau (toutes les 20 secondes)."""
        self.logger.info("Début scan rapide réseau...")
        
        all_devices = {}
        new_devices = []
        
        for network_range in self.network_ranges:
            try:
                network = ipaddress.IPv4Network(network_range)
                ips = [str(ip) for ip in network.hosts()]
                
                # Limiter le scan pour les grands réseaux
                if len(ips) > 254:
                    ips = ips[:254]
                
                # Scan parallèle
                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    futures = {executor.submit(self._scan_single_ip, ip): ip for ip in ips}
                    
                    for future in as_completed(futures):
                        device = future.result()
                        if device:
                            all_devices[device['ip_address']] = device
                            
                            # Vérifier si c'est un nouvel appareil
                            if device['ip_address'] not in self.discovered_devices:
                                new_devices.append(device)
                                self._log_network_event(device['ip_address'], 'new_device', device)
                
            except Exception as e:
                self.logger.error(f"Erreur scan réseau {network_range}: {e}")
        
        # Mettre à jour les appareils existants
        self._update_devices_in_database(all_devices)
        
        # Notifier les nouveaux appareils
        if new_devices and self.new_devices_callback:
            self.new_devices_callback(new_devices)
        
        self.discovered_devices = all_devices
        self.logger.info(f"Scan rapide terminé: {len(all_devices)} appareils trouvés, {len(new_devices)} nouveaux")
    
    def _full_scan_network(self):
        """Scan complet avec tous les ports (toutes les 5 minutes)."""
        self.logger.info("Début scan complet réseau...")
        
        for ip, device in self.discovered_devices.items():
            try:
                # Scan complet des ports
                open_ports = self._scan_ports_full(ip)
                
                # Comparer avec les ports précédents
                old_ports = set(json.loads(device.get('open_ports', '[]')))
                new_ports = set(open_ports)
                
                # Détecter les nouveaux ports ouverts
                if new_ports - old_ports:
                    self._log_network_event(ip, 'ports_opened', {
                        'new_ports': list(new_ports - old_ports),
                        'all_ports': open_ports
                    })
                
                # Mettre à jour en base
                self._update_device_ports(ip, open_ports)
                
            except Exception as e:
                self.logger.warning(f"Erreur scan complet {ip}: {e}")
        
        self.logger.info("Scan complet terminé")
    
    def _update_devices_in_database(self, devices):
        """Met à jour les appareils en base de données."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for ip, device in devices.items():
                # Vérifier si l'appareil existe
                cursor.execute("SELECT * FROM network_devices WHERE ip_address = ?", (ip,))
                existing = cursor.fetchone()
                
                if existing:
                    # Mettre à jour
                    cursor.execute('''
                        UPDATE network_devices SET 
                            mac_address = ?, hostname = ?, manufacturer = ?,
                            device_type = ?, open_ports = ?, last_seen = CURRENT_TIMESTAMP,
                            status = 'online'
                        WHERE ip_address = ?
                    ''', (device['mac_address'], device['hostname'], device['manufacturer'],
                          device['device_type'], device['open_ports'], ip))
                else:
                    # Insérer
                    cursor.execute('''
                        INSERT INTO network_devices 
                        (ip_address, mac_address, hostname, manufacturer, device_type, 
                         open_ports, services, status, risk_score)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (device['ip_address'], device['mac_address'], device['hostname'],
                          device['manufacturer'], device['device_type'], device['open_ports'],
                          device['services'], device['status'], 0))
            
            # Marquer les appareils offline (ceux qui ne répondent plus)
            online_ips = set(devices.keys())
            cursor.execute("SELECT ip_address FROM network_devices WHERE status = 'online'")
            for (old_ip,) in cursor.fetchall():
                if old_ip not in online_ips:
                    cursor.execute("UPDATE network_devices SET status = 'offline' WHERE ip_address = ?", (old_ip,))
                    self._log_network_event(old_ip, 'device_offline', {'reason': 'no_response'})
            
            conn.commit()
    
    def _update_device_ports(self, ip, open_ports):
        """Met à jour les ports ouverts d'un appareil."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE network_devices SET 
                    open_ports = ?, last_seen = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (json.dumps(open_ports), ip))
            conn.commit()
    
    def _log_network_event(self, device_ip, event_type, event_data):
        """Enregistre un événement réseau."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO network_events (device_ip, event_type, event_data)
                VALUES (?, ?, ?)
            ''', (device_ip, event_type, json.dumps(event_data)))
            conn.commit()
    
    def _cleanup_old_data(self):
        """Nettoie les anciennes données (plus de 1 mois)."""
        cutoff_date = datetime.now() - timedelta(days=HISTORY_RETENTION_DAYS)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM network_events WHERE timestamp < ?", (cutoff_date,))
            deleted_rows = cursor.rowcount
            
            # Supprimer les appareils offline depuis plus d'un mois
            cursor.execute('''
                DELETE FROM network_devices 
                WHERE status = 'offline' AND last_seen < ?
            ''', (cutoff_date,))
            deleted_devices = cursor.rowcount
            
            conn.commit()
            
            if deleted_rows > 0 or deleted_devices > 0:
                self.logger.info(f"Nettoyage: {deleted_rows} événements, {deleted_devices} appareils supprimés")
    
    def _quick_scan_loop(self):
        """Boucle de scan rapide."""
        while self.running:
            try:
                start_time = time.time()
                self._quick_scan_network()
                
                # Nettoyage périodique (toutes les heures)
                if int(time.time()) % 3600 < SCAN_INTERVAL_QUICK:
                    self._cleanup_old_data()
                
                # Calculer le temps d'attente pour respecter l'intervalle
                elapsed = time.time() - start_time
                sleep_time = max(0, SCAN_INTERVAL_QUICK - elapsed)
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
            except Exception as e:
                self.logger.error(f"Erreur dans boucle scan rapide: {e}")
                time.sleep(SCAN_INTERVAL_QUICK)
    
    def _full_scan_loop(self):
        """Boucle de scan complet."""
        while self.running:
            try:
                self._full_scan_network()
                time.sleep(SCAN_INTERVAL_FULL)
            except Exception as e:
                self.logger.error(f"Erreur dans boucle scan complet: {e}")
                time.sleep(SCAN_INTERVAL_FULL)
    
    def start_monitoring(self, new_devices_callback=None):
        """Démarre la surveillance réseau."""
        if self.running:
            self.logger.warning("Surveillance déjà en cours")
            return
        
        self.running = True
        self.new_devices_callback = new_devices_callback
        
        # Démarrer le thread de scan rapide
        self.scan_thread = threading.Thread(target=self._quick_scan_loop, daemon=True)
        self.scan_thread.start()
        
        # Démarrer le thread de scan complet
        self.full_scan_thread = threading.Thread(target=self._full_scan_loop, daemon=True)
        self.full_scan_thread.start()
        
        self.logger.info("Surveillance réseau démarrée")
    
    def stop_monitoring(self):
        """Arrête la surveillance réseau."""
        self.running = False
        
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        if self.full_scan_thread:
            self.full_scan_thread.join(timeout=5)
        
        self.logger.info("Surveillance réseau arrêtée")
    
    def get_devices(self):
        """Retourne tous les appareils connus."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM network_devices ORDER BY last_seen DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_recent_events(self, limit=50):
        """Retourne les événements récents."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM network_events 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def blacklist_device(self, ip_address):
        """Ajoute un appareil en blacklist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE network_devices SET is_blacklisted = 1, risk_score = 10
                WHERE ip_address = ?
            ''', (ip_address,))
            conn.commit()
            self._log_network_event(ip_address, 'blacklisted', {'action': 'blacklisted'})
    
    def unblacklist_device(self, ip_address):
        """Retire un appareil de la blacklist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE network_devices SET is_blacklisted = 0, risk_score = 0
                WHERE ip_address = ?
            ''', (ip_address,))
            conn.commit()
            self._log_network_event(ip_address, 'unblacklisted', {'action': 'unblacklisted'})

# Fonctions de compatibilité avec l'ancien code
def get_local_subnet():
    """Déduit le sous-réseau local (ex: 192.168.1.) basé sur l'IP de la machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '192.168.1.1'
    finally:
        s.close()
    
    parts = IP.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}."

def discover_devices(progress_callback=None, finished_callback=None):
    """Effectue un balayage réseau avec le nouveau scanner."""
    scanner = NetworkScanner()
    devices = []
    
    def on_new_devices(new_devices):
        devices.extend(new_devices)
        if finished_callback:
            finished_callback(len(devices))
    
    # Scanner une fois
    scanner._quick_scan_network()
    return scanner.discovered_devices

# Test du module
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    def on_new_devices(devices):
        print(f"Nouveaux appareils détectés: {len(devices)}")
        for device in devices:
            print(f"  - {device['ip_address']} ({device['hostname'] or 'Unknown'})")
    
    scanner = NetworkScanner()
    scanner.start_monitoring(on_new_devices)
    
    try:
        print("Surveillance réseau en cours... Appuyez sur Ctrl+C pour arrêter.")
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nArrêt...")
        scanner.stop_monitoring()
