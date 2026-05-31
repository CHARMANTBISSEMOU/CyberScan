"""
CyberScan Packet Capture
Module de capture et d'analyse de trafic réseau en temps réel.
Fonctionne en local avec Scapy pour l'analyse Deep Packet Inspection.
"""

import threading
import time
import sqlite3
import logging
import json
import queue
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
import socket
import struct
import re

try:
    from scapy.all import sniff, get_if_list, conf, IP, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.inet import TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy non disponible. Capture de paquets désactivée.")

# Configuration
PACKET_BUFFER_SIZE = 10000  # paquets max en mémoire
FLOW_TIMEOUT = 300  # secondes pour considérer un flux terminé
ALERT_THRESHOLD_CONNECTIONS = 100  # connexions/min pour alerte
ALERT_THRESHOLD_DATA_TRANSFER = 100 * 1024 * 1024  # 100MB/min
PACKET_RETENTION_DAYS = 30
SUSPICIOUS_DOMAINS = [
    'torproject.org', 'anonymous.org', 'proxy.org',
    'darkweb', 'onion', 'i2p', 'freedom'
]

# Ports et protocoles à surveiller
MONITORED_PROTOCOLS = {
    'HTTP': [80, 8080, 8000, 3000],
    'HTTPS': [443, 8443],
    'FTP': [21, 2121],
    'SMTP': [25, 587, 465],
    'POP3': [110, 995],
    'IMAP': [143, 993],
    'DNS': [53],
    'SSH': [22],
    'TELNET': [23],
    'RDP': [3389],
    'SMB': [139, 445]
}

# Signatures de trafic suspect
SUSPICIOUS_SIGNATURES = {
    'TOR': [b'GET /tor/', b'.onion', b'torproject.org'],
    'P2P': [b'BitTorrent', b'bittorrent', b'torrent', b'peer'],
    'IRC': [b'PRIVMSG', b'JOIN ', b'PART ', b'NICK '],
    'MALWARE': [b'cmd.exe', b'powershell', b'wget ', b'curl '],
    'C2': [b'bot', b'c2', b'command', b'control']
}

class PacketCapture:
    def __init__(self, db_path="cyberscan.db"):
        self.db_path = db_path
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None
        self.interface = None
        self.packet_queue = queue.Queue(maxsize=PACKET_BUFFER_SIZE)
        self.active_flows = {}
        self.statistics = defaultdict(int)
        self.alerts_callback = None
        self.logger = logging.getLogger(__name__)
        
        # Buffer circulaire pour les paquets récents
        self.recent_packets = deque(maxlen=1000)
        
        # Initialiser la base de données
        self._init_database()
        
        # Détecter l'interface réseau
        self._detect_interface()
    
    def _init_database(self):
        """Crée les tables pour la capture de paquets."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des paquets bruts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    size INTEGER,
                    flags TEXT,
                    payload_hash TEXT,
                    flow_id TEXT,
                    risk_score INTEGER DEFAULT 0,
                    is_suspicious BOOLEAN DEFAULT 0
                )
            ''')
            
            # Table des flux réseau
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT UNIQUE NOT NULL,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    packets_count INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low',
                    is_suspicious BOOLEAN DEFAULT 0
                )
            ''')
            
            # Table des alertes de trafic
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged BOOLEAN DEFAULT 0
                )
            ''')
            
            # Table des statistiques agrégées
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    protocol TEXT,
                    bytes_count INTEGER DEFAULT 0,
                    packets_count INTEGER DEFAULT 0,
                    flows_count INTEGER DEFAULT 0,
                    alerts_count INTEGER DEFAULT 0
                )
            ''')
            
            # Index pour performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_timestamp ON network_packets(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packet_flow ON network_packets(flow_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_start ON network_flows(start_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON traffic_alerts(timestamp)')
            
            conn.commit()
            self.logger.info("Base de données de trafic initialisée")
    
    def _detect_interface(self):
        """Détecte automatiquement l'interface réseau active."""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy non disponible, impossible de détecter l'interface")
            return False
        
        try:
            interfaces = get_if_list()
            
            # Chercher l'interface principale (Wi-Fi ou Ethernet)
            for iface in interfaces:
                if any(keyword in iface.lower() for keyword in ['wi-fi', 'wifi', 'ethernet', 'eth', 'en', 'wl']):
                    self.interface = iface
                    self.logger.info(f"Interface réseau détectée: {iface}")
                    return True
            
            # Fallback : première interface disponible
            if interfaces:
                self.interface = interfaces[0]
                self.logger.info(f"Interface par défaut utilisée: {self.interface}")
                return True
            else:
                self.logger.error("Aucune interface réseau détectée")
                return False
                
        except Exception as e:
            self.logger.error(f"Erreur détection interface: {e}")
            return False
    
    def _generate_flow_id(self, packet):
        """Génère un ID unique pour le flux réseau."""
        try:
            if IP in packet:
                ip = packet[IP]
                src_ip, dst_ip = ip.src, ip.dst
                
                # Normaliser l'ordre (toujours la plus petite IP en premier)
                if src_ip < dst_ip:
                    flow_base = f"{src_ip}:{dst_ip}"
                else:
                    flow_base = f"{dst_ip}:{src_ip}"
                
                # Ajouter les ports si TCP/UDP
                if TCP in packet:
                    src_port, dst_port = packet[TCP].sport, packet[TCP].dstport
                    if src_ip < dst_ip:
                        flow_id = f"{flow_base}:{src_port}-{dst_port}:TCP"
                    else:
                        flow_id = f"{flow_base}:{dst_port}-{src_port}:TCP"
                elif UDP in packet:
                    src_port, dst_port = packet[UDP].sport, packet[UDP].dport
                    if src_ip < dst_ip:
                        flow_id = f"{flow_base}:{src_port}-{dst_port}:UDP"
                    else:
                        flow_id = f"{flow_base}:{dst_port}-{src_port}:UDP"
                else:
                    flow_id = f"{flow_base}:ICMP"
                
                return flow_id
        except:
            pass
        
        return None
    
    def _calculate_risk_score(self, packet):
        """Calcule un score de risque pour un paquet."""
        score = 0
        reasons = []
        
        try:
            if IP in packet:
                ip = packet[IP]
                
                # Vérifier les IPs locales vs externes
                src_local = self._is_local_ip(ip.src)
                dst_local = self._is_local_ip(ip.dst)
                
                # Connexion vers l'extérieur
                if src_local and not dst_local:
                    score += 1
                    reasons.append("external_connection")
                
                # Ports suspects
                if TCP in packet:
                    dst_port = packet[TCP].dstport
                    if dst_port in [6667, 6668, 6669]:  # IRC
                        score += 3
                        reasons.append("irc_port")
                    elif dst_port in [6881, 6882, 6883, 6884, 6885]:  # BitTorrent
                        score += 3
                        reasons.append("bittorrent_port")
                
                # Analyse du payload
                if Raw in packet:
                    payload = packet[Raw].load
                    for threat_type, signatures in SUSPICIOUS_SIGNATURES.items():
                        for sig in signatures:
                            if sig in payload:
                                score += 2
                                reasons.append(threat_type)
                                break
                
                # Taille anormale
                if len(packet) > 8000:
                    score += 1
                    reasons.append("large_packet")
        
        except Exception as e:
            self.logger.warning(f"Erreur calcul risque: {e}")
        
        return min(score, 10), reasons
    
    def _is_local_ip(self, ip):
        """Vérifie si une IP est locale."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # Plages privées
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True
            elif first == 127:
                return True
            
            return False
        except:
            return False
    
    def _analyze_packet(self, packet):
        """Analyse un paquet et extrait les informations."""
        try:
            if not IP in packet:
                return None
            
            ip = packet[IP]
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'protocol': ip.proto,
                'size': len(packet),
                'flow_id': self._generate_flow_id(packet)
            }
            
            # Ports TCP/UDP
            if TCP in packet:
                tcp = packet[TCP]
                packet_info.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'flags': str(tcp.flags),
                    'protocol_name': 'TCP'
                })
            elif UDP in packet:
                udp = packet[UDP]
                packet_info.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'flags': '',
                    'protocol_name': 'UDP'
                })
            else:
                packet_info.update({
                    'src_port': 0,
                    'dst_port': 0,
                    'flags': '',
                    'protocol_name': 'ICMP'
                })
            
            # Hash du payload pour déduplication
            if Raw in packet:
                payload = packet[Raw].load[:512]  # Limiter à 512 bytes
                packet_info['payload_hash'] = hashlib.md5(payload).hexdigest()
            else:
                packet_info['payload_hash'] = ''
            
            # Calcul du risque
            risk_score, risk_reasons = self._calculate_risk_score(packet)
            packet_info['risk_score'] = risk_score
            packet_info['is_suspicious'] = risk_score >= 5
            
            return packet_info
            
        except Exception as e:
            self.logger.warning(f"Erreur analyse paquet: {e}")
            return None
    
    def _update_flow(self, packet_info):
        """Met à jour les informations du flux."""
        flow_id = packet_info.get('flow_id')
        if not flow_id:
            return
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Vérifier si le flux existe
                cursor.execute("SELECT * FROM network_flows WHERE flow_id = ?", (flow_id,))
                existing = cursor.fetchone()
                
                if existing:
                    # Mettre à jour le flux existant
                    cursor.execute('''
                        UPDATE network_flows SET 
                            end_time = CURRENT_TIMESTAMP,
                            packets_count = packets_count + 1,
                            bytes_sent = bytes_sent + ?,
                            bytes_received = bytes_received + ?
                        WHERE flow_id = ?
                    ''', (packet_info['size'], 0, flow_id))
                else:
                    # Créer un nouveau flux
                    cursor.execute('''
                        INSERT INTO network_flows 
                        (flow_id, protocol, src_ip, dst_ip, src_port, dst_port, 
                         start_time, end_time, bytes_sent, bytes_received, packets_count)
                        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?, 1)
                    ''', (flow_id, packet_info['protocol_name'], packet_info['src_ip'],
                          packet_info['dst_ip'], packet_info['src_port'], packet_info['dst_port'],
                          packet_info['size'], 0))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Erreur mise à jour flux: {e}")
    
    def _packet_handler(self, packet):
        """Gestionnaire principal pour les paquets capturés."""
        try:
            # Analyser le paquet
            packet_info = self._analyze_packet(packet)
            if not packet_info:
                return
            
            # Ajouter au buffer circulaire
            self.recent_packets.append(packet_info)
            
            # Mettre en file pour traitement
            try:
                self.packet_queue.put_nowait(packet_info)
            except queue.Full:
                # Buffer plein, ignorer les plus anciens
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(packet_info)
                except:
                    pass
            
            # Mettre à jour le flux
            self._update_flow(packet_info)
            
            # Mettre à jour les statistiques
            self.statistics['packets_captured'] += 1
            self.statistics['bytes_captured'] += packet_info['size']
            
            # Vérifier les alertes
            if packet_info['is_suspicious']:
                self._check_alerts(packet_info)
                
        except Exception as e:
            self.logger.error(f"Erreur traitement paquet: {e}")
    
    def _check_alerts(self, packet_info):
        """Vérifie si une alerte doit être générée."""
        try:
            alert_type = None
            severity = 'medium'
            details = {}
            
            # Alertes basées sur le risque
            if packet_info['risk_score'] >= 7:
                alert_type = 'high_risk_packet'
                severity = 'high'
                details['risk_score'] = packet_info['risk_score']
            
            # Alertes de connexion externe
            elif self._is_local_ip(packet_info['src_ip']) and not self._is_local_ip(packet_info['dst_ip']):
                alert_type = 'external_connection'
                severity = 'low'
                details['external_ip'] = packet_info['dst_ip']
            
            # Alertes de ports suspects
            elif packet_info['dst_port'] in [6667, 6668, 6669]:  # IRC
                alert_type = 'suspicious_port'
                severity = 'medium'
                details['port'] = packet_info['dst_port']
                details['service'] = 'IRC'
            
            if alert_type:
                self._create_alert(alert_type, severity, packet_info, details)
                
        except Exception as e:
            self.logger.error(f"Erreur vérification alertes: {e}")
    
    def _create_alert(self, alert_type, severity, packet_info, details):
        """Crée une alerte de trafic."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO traffic_alerts 
                    (alert_type, severity, src_ip, dst_ip, protocol, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (alert_type, severity, packet_info['src_ip'], packet_info['dst_ip'],
                      packet_info['protocol_name'], json.dumps(details)))
                conn.commit()
            
            # Notifier le callback
            if self.alerts_callback:
                alert = {
                    'type': alert_type,
                    'severity': severity,
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'timestamp': datetime.now().isoformat(),
                    'details': details
                }
                self.alerts_callback(alert)
                
        except Exception as e:
            self.logger.error(f"Erreur création alerte: {e}")
    
    def _process_packets(self):
        """Traite les paquets en file d'attente."""
        while self.running:
            try:
                # Récupérer les paquets à traiter
                packets_to_process = []
                
                try:
                    while len(packets_to_process) < 100:  # Traiter par lots de 100
                        packet = self.packet_queue.get(timeout=1)
                        packets_to_process.append(packet)
                except queue.Empty:
                    pass
                
                # Traiter les paquets
                for packet_info in packets_to_process:
                    self._store_packet(packet_info)
                
                # Nettoyage des flux expirés
                self._cleanup_expired_flows()
                
            except Exception as e:
                self.logger.error(f"Erreur traitement paquets: {e}")
    
    def _store_packet(self, packet_info):
        """Stocke un paquet en base de données."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO network_packets 
                    (src_ip, dst_ip, src_port, dst_port, protocol, size, 
                     flags, payload_hash, flow_id, risk_score, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (packet_info['src_ip'], packet_info['dst_ip'],
                      packet_info['src_port'], packet_info['dst_port'],
                      packet_info['protocol_name'], packet_info['size'],
                      packet_info['flags'], packet_info['payload_hash'],
                      packet_info['flow_id'], packet_info['risk_score'],
                      packet_info['is_suspicious']))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Erreur stockage paquet: {e}")
    
    def _cleanup_expired_flows(self):
        """Nettoie les flux expirés et les anciennes données."""
        try:
            cutoff_time = datetime.now() - timedelta(seconds=FLOW_TIMEOUT)
            cutoff_date = datetime.now() - timedelta(days=PACKET_RETENTION_DAYS)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Marquer les flux expirés comme terminés
                cursor.execute('''
                    UPDATE network_flows SET end_time = ?
                    WHERE end_time IS NULL AND start_time < ?
                ''', (cutoff_time, cutoff_time))
                
                # Supprimer les anciens paquets
                cursor.execute("DELETE FROM network_packets WHERE timestamp < ?", (cutoff_date,))
                deleted_packets = cursor.rowcount
                
                # Supprimer les anciennes alertes
                cursor.execute("DELETE FROM traffic_alerts WHERE timestamp < ?", (cutoff_date,))
                deleted_alerts = cursor.rowcount
                
                conn.commit()
                
                if deleted_packets > 0 or deleted_alerts > 0:
                    self.logger.info(f"Nettoyage: {deleted_packets} paquets, {deleted_alerts} alertes supprimés")
                    
        except Exception as e:
            self.logger.error(f"Erreur nettoyage: {e}")
    
    def _capture_loop(self):
        """Boucle principale de capture."""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy non disponible, capture impossible")
            return
        
        try:
            # Construire le filtre BPF
            filter_expr = "tcp or udp or icmp"
            
            self.logger.info(f"Démarrage capture sur {self.interface} avec filtre: {filter_expr}")
            
            # Démarrer la capture
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=filter_expr,
                store=0,  # Ne pas stocker en mémoire
                stop_filter=lambda x: not self.running
            )
            
        except Exception as e:
            self.logger.error(f"Erreur capture: {e}")
        finally:
            self.logger.info("Capture arrêtée")
    
    def start_capture(self, alerts_callback=None):
        """Démarre la capture de paquets."""
        if self.running:
            self.logger.warning("Capture déjà en cours")
            return False
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy non disponible, impossible de démarrer la capture")
            return False
        
        if not self.interface:
            self.logger.error("Aucune interface réseau détectée")
            return False
        
        self.running = True
        self.alerts_callback = alerts_callback
        
        # Démarrer le thread de capture
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        # Démarrer le thread de traitement
        self.analysis_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.analysis_thread.start()
        
        self.logger.info("Capture de paquets démarrée")
        return True
    
    def stop_capture(self):
        """Arrête la capture de paquets."""
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        
        self.logger.info("Capture de paquets arrêtée")
    
    def get_recent_packets(self, limit=100):
        """Retourne les paquets récents."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM network_packets 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_active_flows(self, limit=50):
        """Retourne les flux actifs."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM network_flows 
                WHERE end_time IS NULL OR end_time > datetime('now', '-5 minutes')
                ORDER BY start_time DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alerts(self, limit=50, unacknowledged_only=False):
        """Retourne les alertes de trafic."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM traffic_alerts"
            params = []
            
            if unacknowledged_only:
                query += " WHERE acknowledged = 0"
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self):
        """Retourne les statistiques de trafic."""
        stats = dict(self.statistics)
        
        # Ajouter les statistiques de la base de données
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Paquets totaux
            cursor.execute("SELECT COUNT(*), SUM(size) FROM network_packets WHERE timestamp > datetime('now', '-1 hour')")
            result = cursor.fetchone()
            stats['packets_last_hour'] = result[0] or 0
            stats['bytes_last_hour'] = result[1] or 0
            
            # Flux actifs
            cursor.execute("SELECT COUNT(*) FROM network_flows WHERE end_time IS NULL")
            stats['active_flows'] = cursor.fetchone()[0] or 0
            
            # Alertes récentes
            cursor.execute("SELECT COUNT(*) FROM traffic_alerts WHERE timestamp > datetime('now', '-1 hour')")
            stats['alerts_last_hour'] = cursor.fetchone()[0] or 0
        
        return stats
    
    def acknowledge_alert(self, alert_id):
        """Marque une alerte comme acquittée."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE traffic_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            conn.commit()

# Test du module
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    def on_alert(alert):
        print(f"ALERTE: {alert['type']} - {alert['src_ip']} -> {alert['dst_ip']}")
    
    capture = PacketCapture()
    
    if capture.start_capture(on_alert):
        try:
            print("Capture en cours... Appuyez sur Ctrl+C pour arrêter.")
            while True:
                time.sleep(10)
                stats = capture.get_statistics()
                print(f"Statistiques: {stats['packets_captured']} paquets, {stats['active_flows']} flux actifs")
        except KeyboardInterrupt:
            print("\nArrêt...")
            capture.stop_capture()
    else:
        print("Impossible de démarrer la capture")
