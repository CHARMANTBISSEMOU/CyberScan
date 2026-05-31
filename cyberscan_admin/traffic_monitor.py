"""
CyberScan Traffic Monitor
Module de surveillance de trafic réseau sans dépendance Scapy.
Utilise les sockets Windows et l'API système pour la capture de base.
"""

import threading
import time
import sqlite3
import logging
import json
import socket
import struct
import ctypes
from ctypes import wintypes
import psutil
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Configuration Windows pour la capture réseau
PACKET_BUFFER_SIZE = 10000
FLOW_TIMEOUT = 300
ALERT_THRESHOLD_CONNECTIONS = 100
PACKET_RETENTION_DAYS = 30

# Structures Windows pour les statistiques réseau
class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ('dwState', wintypes.DWORD),
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwRemoteAddr', wintypes.DWORD),
        ('dwRemotePort', wintypes.DWORD)
    ]

class MIB_UDPROW(ctypes.Structure):
    _fields_ = [
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwRemoteAddr', wintypes.DWORD),
        ('dwRemotePort', wintypes.DWORD)
    ]

# Constants Windows
MIB_TCP_STATE_LISTEN = 2
MIB_TCP_STATE_ESTAB = 5

class TrafficMonitor:
    def __init__(self, db_path="cyberscan.db"):
        self.db_path = db_path
        self.running = False
        self.monitor_thread = None
        self.alerts_callback = None
        self.logger = logging.getLogger(__name__)
        
        # Statistiques
        self.statistics = defaultdict(int)
        self.active_connections = {}
        self.connection_history = deque(maxlen=1000)
        
        # Initialiser la base de données
        self._init_database()
        
        # Charger les DLL Windows
        self._load_windows_dlls()
    
    def _load_windows_dlls(self):
        """Charge les DLL Windows pour la surveillance réseau."""
        try:
            self.iphlpapi = ctypes.windll.iphlpapi
            self.ws2_32 = ctypes.windll.ws2_32
            
            # Définir les fonctions
            self.iphlpapi.GetTcpTable.restype = wintypes.DWORD
            self.iphlpapi.GetTcpTable.argtypes = [
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL
            ]
            
            self.iphlpapi.GetUdpTable.restype = wintypes.DWORD
            self.iphlpapi.GetUdpTable.argtypes = [
                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL
            ]
            
            self.logger.info("DLL Windows chargées avec succès")
            
        except Exception as e:
            self.logger.error(f"Erreur chargement DLL Windows: {e}")
    
    def _init_database(self):
        """Crée les tables pour la surveillance de trafic."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des connexions réseau
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    protocol TEXT,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    state TEXT,
                    process_name TEXT,
                    pid INTEGER,
                    risk_score INTEGER DEFAULT 0,
                    is_suspicious BOOLEAN DEFAULT 0
                )
            ''')
            
            # Table des flux de trafic
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT UNIQUE NOT NULL,
                    protocol TEXT,
                    local_ip TEXT,
                    remote_ip TEXT,
                    local_port INTEGER,
                    remote_port INTEGER,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    connection_count INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low'
                )
            ''')
            
            # Table des alertes de trafic
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    local_ip TEXT,
                    remote_ip TEXT,
                    protocol TEXT,
                    process_name TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged BOOLEAN DEFAULT 0
                )
            ''')
            
            # Table des statistiques
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    protocol TEXT,
                    connections_count INTEGER DEFAULT 0,
                    bytes_transferred INTEGER DEFAULT 0,
                    alert_count INTEGER DEFAULT 0
                )
            ''')
            
            # Index
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON network_connections(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_start ON traffic_flows(start_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON traffic_alerts(timestamp)')
            
            conn.commit()
            self.logger.info("Base de données de trafic initialisée")
    
    def _ip_to_string(self, ip_int):
        """Convertit un entier IP en string."""
        try:
            return socket.inet_ntoa(struct.pack('!I', ip_int))
        except:
            return "0.0.0.0"
    
    def _port_to_int(self, port_int):
        """Convertit un port Windows en port standard."""
        return socket.ntohs(port_int)
    
    def _get_process_name(self, pid):
        """Obtient le nom du processus depuis son PID."""
        try:
            if pid == 0:
                return "System"
            process = psutil.Process(pid)
            return process.name()
        except:
            return "Unknown"
    
    def _is_local_ip(self, ip_str):
        """Vérifie si une IP est locale."""
        try:
            parts = ip_str.split('.')
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
    
    def _calculate_risk_score(self, connection):
        """Calcule un score de risque pour une connexion."""
        score = 0
        reasons = []
        
        try:
            # Connexion vers l'extérieur
            if self._is_local_ip(connection['local_ip']) and not self._is_local_ip(connection['remote_ip']):
                score += 1
                reasons.append("external_connection")
            
            # Ports suspects
            remote_port = connection['remote_port']
            if remote_port in [6667, 6668, 6669]:  # IRC
                score += 3
                reasons.append("irc_port")
            elif remote_port in [6881, 6882, 6883, 6884, 6885]:  # BitTorrent
                score += 3
                reasons.append("bittorrent_port")
            elif remote_port in [1337, 31337, 12345]:  # Backdoors
                score += 4
                reasons.append("backdoor_port")
            
            # Processus suspects
            process_name = connection.get('process_name', '').lower()
            if any(sus in process_name for sus in ['torrent', 'utorrent', 'bittorrent', 'emule']):
                score += 3
                reasons.append("p2p_process")
            elif any(sus in process_name for sus in ['tor', 'proxy', 'vpn']):
                score += 3
                reasons.append("anonymizer_process")
            
            # État de connexion
            if connection.get('state') == 'ESTABLISHED' and not self._is_local_ip(connection['remote_ip']):
                score += 1
                reasons.append("established_external")
            
        except Exception as e:
            self.logger.warning(f"Erreur calcul risque: {e}")
        
        return min(score, 10), reasons
    
    def _get_tcp_connections(self):
        """Récupère les connexions TCP via l'API Windows."""
        connections = []
        
        try:
            # Préparer le buffer
            size = wintypes.DWORD(0)
            result = self.iphlpapi.GetTcpTable(None, ctypes.byref(size), False)
            
            if result != 0:  # ERROR_INSUFFICIENT_BUFFER
                buffer = ctypes.create_string_buffer(size.value)
                result = self.iphlpapi.GetTcpTable(buffer, ctypes.byref(size), False)
                
                if result == 0:
                    # Parser la table TCP
                    ptr = ctypes.cast(buffer, ctypes.POINTER(MIB_TCPROW))
                    count = (size.value - ctypes.sizeof(wintypes.DWORD)) // ctypes.sizeof(MIB_TCPROW)
                    
                    for i in range(count):
                        row = ptr[i]
                        
                        # Convertir les adresses et ports
                        local_ip = self._ip_to_string(row.dwLocalAddr)
                        remote_ip = self._ip_to_string(row.dwRemoteAddr)
                        local_port = self._port_to_int(row.dwLocalPort)
                        remote_port = self._port_to_int(row.dwRemotePort)
                        
                        # État de connexion
                        state_map = {
                            1: 'CLOSED',
                            2: 'LISTEN',
                            3: 'SYN_SENT',
                            4: 'SYN_RECEIVED',
                            5: 'ESTABLISHED',
                            6: 'FIN_WAIT_1',
                            7: 'FIN_WAIT_2',
                            8: 'CLOSE_WAIT',
                            9: 'CLOSING',
                            10: 'LAST_ACK',
                            11: 'TIME_WAIT'
                        }
                        state = state_map.get(row.dwState, 'UNKNOWN')
                        
                        # Ignorer les connexions en écoute si remote_ip = 0.0.0.0
                        if state == 'LISTEN' and remote_ip == '0.0.0.0':
                            continue
                        
                        connections.append({
                            'protocol': 'TCP',
                            'local_ip': local_ip,
                            'local_port': local_port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'state': state,
                            'timestamp': datetime.now()
                        })
        
        except Exception as e:
            self.logger.warning(f"Erreur récupération connexions TCP: {e}")
        
        return connections
    
    def _get_udp_connections(self):
        """Récupère les connexions UDP via l'API Windows."""
        connections = []
        
        try:
            # Préparer le buffer
            size = wintypes.DWORD(0)
            result = self.iphlpapi.GetUdpTable(None, ctypes.byref(size), False)
            
            if result != 0:  # ERROR_INSUFFICIENT_BUFFER
                buffer = ctypes.create_string_buffer(size.value)
                result = self.iphlpapi.GetUdpTable(buffer, ctypes.byref(size), False)
                
                if result == 0:
                    # Parser la table UDP
                    ptr = ctypes.cast(buffer, ctypes.POINTER(MIB_UDPROW))
                    count = (size.value - ctypes.sizeof(wintypes.DWORD)) // ctypes.sizeof(MIB_UDPROW)
                    
                    for i in range(count):
                        row = ptr[i]
                        
                        # Convertir les adresses et ports
                        local_ip = self._ip_to_string(row.dwLocalAddr)
                        remote_ip = self._ip_to_string(row.dwRemoteAddr)
                        local_port = self._port_to_int(row.dwLocalPort)
                        remote_port = self._port_to_int(row.dwRemotePort)
                        
                        connections.append({
                            'protocol': 'UDP',
                            'local_ip': local_ip,
                            'local_port': local_port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'state': 'ACTIVE',
                            'timestamp': datetime.now()
                        })
        
        except Exception as e:
            self.logger.warning(f"Erreur récupération connexions UDP: {e}")
        
        return connections
    
    def _enrich_connections_with_processes(self, connections):
        """Enrichit les connexions avec les informations de processus."""
        try:
            # Utiliser psutil pour obtenir les connexions avec processus
            psutil_connections = psutil.net_connections(kind='inet')
            
            # Créer un mapping des connexions
            connection_map = {}
            for conn in connections:
                key = (conn['protocol'], conn['local_ip'], conn['local_port'], 
                      conn['remote_ip'], conn['remote_port'])
                connection_map[key] = conn
            
            # Enrichir avec les informations de processus
            for ps_conn in psutil_connections:
                if ps_conn.status == 'ESTABLISHED' or ps_conn.status == 'LISTEN':
                    protocol = 'TCP' if ps_conn.type == socket.SOCK_STREAM else 'UDP'
                    key = (protocol, ps_conn.laddr.ip, ps_conn.laddr.port,
                          ps_conn.raddr.ip if ps_conn.raddr else '0.0.0.0',
                          ps_conn.raddr.port if ps_conn.raddr else 0)
                    
                    if key in connection_map:
                        connection_map[key]['pid'] = ps_conn.pid
                        connection_map[key]['process_name'] = self._get_process_name(ps_conn.pid)
        
        except Exception as e:
            self.logger.warning(f"Erreur enrichissement processus: {e}")
        
        return connections
    
    def _monitor_loop(self):
        """Boucle principale de surveillance."""
        self.logger.info("Démarrage surveillance réseau")
        
        while self.running:
            try:
                # Récupérer les connexions
                tcp_connections = self._get_tcp_connections()
                udp_connections = self._get_udp_connections()
                all_connections = tcp_connections + udp_connections
                
                # Enrichir avec les processus
                all_connections = self._enrich_connections_with_processes(all_connections)
                
                # Analyser les connexions
                for conn in all_connections:
                    self._analyze_connection(conn)
                
                # Nettoyer les anciennes données
                self._cleanup_old_data()
                
                # Mettre à jour les statistiques
                self.statistics['connections_checked'] = len(all_connections)
                self.statistics['monitoring_cycles'] += 1
                
                # Attendre avant le prochain cycle
                time.sleep(5)  # Vérifier toutes les 5 secondes
                
            except Exception as e:
                self.logger.error(f"Erreur dans boucle de surveillance: {e}")
                time.sleep(5)
        
        self.logger.info("Surveillance réseau arrêtée")
    
    def _analyze_connection(self, connection):
        """Analyse une connexion et détecte les anomalies."""
        try:
            # Calculer le risque
            risk_score, risk_reasons = self._calculate_risk_score(connection)
            connection['risk_score'] = risk_score
            connection['is_suspicious'] = risk_score >= 5
            
            # Stocker la connexion
            self._store_connection(connection)
            
            # Vérifier les alertes
            if connection['is_suspicious']:
                self._check_connection_alerts(connection, risk_reasons)
            
            # Ajouter à l'historique
            self.connection_history.append(connection)
            
        except Exception as e:
            self.logger.error(f"Erreur analyse connexion: {e}")
    
    def _store_connection(self, connection):
        """Stocke une connexion en base de données."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO network_connections 
                    (protocol, local_ip, local_port, remote_ip, remote_port, 
                     state, process_name, pid, risk_score, is_suspicious)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (connection['protocol'], connection['local_ip'], connection['local_port'],
                      connection['remote_ip'], connection['remote_port'], connection['state'],
                      connection.get('process_name'), connection.get('pid'),
                      connection['risk_score'], connection['is_suspicious']))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Erreur stockage connexion: {e}")
    
    def _check_connection_alerts(self, connection, risk_reasons):
        """Vérifie si une alerte doit être générée pour une connexion."""
        try:
            alert_type = None
            severity = 'medium'
            details = {'risk_reasons': risk_reasons}
            
            # Alertes basées sur le risque
            if connection['risk_score'] >= 7:
                alert_type = 'high_risk_connection'
                severity = 'high'
            
            # Alertes spécifiques
            elif 'external_connection' in risk_reasons and connection['risk_score'] >= 4:
                alert_type = 'suspicious_external_connection'
                severity = 'medium'
            
            elif 'p2p_process' in risk_reasons:
                alert_type = 'p2p_activity_detected'
                severity = 'medium'
                details['process'] = connection.get('process_name')
            
            elif 'backdoor_port' in risk_reasons:
                alert_type = 'potential_backdoor'
                severity = 'high'
                details['port'] = connection['remote_port']
            
            if alert_type:
                self._create_alert(alert_type, severity, connection, details)
                
        except Exception as e:
            self.logger.error(f"Erreur vérification alertes: {e}")
    
    def _create_alert(self, alert_type, severity, connection, details):
        """Crée une alerte de trafic."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO traffic_alerts 
                    (alert_type, severity, local_ip, remote_ip, protocol, 
                     process_name, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (alert_type, severity, connection['local_ip'], connection['remote_ip'],
                      connection['protocol'], connection.get('process_name'),
                      json.dumps(details)))
                conn.commit()
            
            # Notifier le callback
            if self.alerts_callback:
                alert = {
                    'type': alert_type,
                    'severity': severity,
                    'local_ip': connection['local_ip'],
                    'remote_ip': connection['remote_ip'],
                    'protocol': connection['protocol'],
                    'process_name': connection.get('process_name'),
                    'timestamp': datetime.now().isoformat(),
                    'details': details
                }
                self.alerts_callback(alert)
                
        except Exception as e:
            self.logger.error(f"Erreur création alerte: {e}")
    
    def _cleanup_old_data(self):
        """Nettoie les anciennes données."""
        try:
            cutoff_date = datetime.now() - timedelta(days=PACKET_RETENTION_DAYS)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Supprimer les anciennes connexions
                cursor.execute("DELETE FROM network_connections WHERE timestamp < ?", (cutoff_date,))
                deleted_connections = cursor.rowcount
                
                # Supprimer les anciennes alertes
                cursor.execute("DELETE FROM traffic_alerts WHERE timestamp < ?", (cutoff_date,))
                deleted_alerts = cursor.rowcount
                
                conn.commit()
                
                if deleted_connections > 0 or deleted_alerts > 0:
                    self.logger.info(f"Nettoyage: {deleted_connections} connexions, {deleted_alerts} alertes supprimées")
                    
        except Exception as e:
            self.logger.error(f"Erreur nettoyage: {e}")
    
    def start_monitoring(self, alerts_callback=None):
        """Démarre la surveillance réseau."""
        if self.running:
            self.logger.warning("Surveillance déjà en cours")
            return False
        
        self.running = True
        self.alerts_callback = alerts_callback
        
        # Démarrer le thread de surveillance
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Surveillance réseau démarrée")
        return True
    
    def stop_monitoring(self):
        """Arrête la surveillance réseau."""
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Surveillance réseau arrêtée")
    
    def get_recent_connections(self, limit=100):
        """Retourne les connexions récentes."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM network_connections 
                ORDER BY timestamp DESC 
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
            
            # Connexions totales
            cursor.execute("SELECT COUNT(*) FROM network_connections WHERE timestamp > datetime('now', '-1 hour')")
            stats['connections_last_hour'] = cursor.fetchone()[0] or 0
            
            # Alertes récentes
            cursor.execute("SELECT COUNT(*) FROM traffic_alerts WHERE timestamp > datetime('now', '-1 hour')")
            stats['alerts_last_hour'] = cursor.fetchone()[0] or 0
            
            # Connexions suspectes
            cursor.execute("SELECT COUNT(*) FROM network_connections WHERE is_suspicious = 1 AND timestamp > datetime('now', '-1 hour')")
            stats['suspicious_connections_last_hour'] = cursor.fetchone()[0] or 0
        
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
        print(f"ALERTE: {alert['type']} - {alert['local_ip']} -> {alert['remote_ip']} ({alert.get('process_name', 'Unknown')})")
    
    monitor = TrafficMonitor()
    
    if monitor.start_monitoring(on_alert):
        try:
            print("Surveillance en cours... Appuyez sur Ctrl+C pour arrêter.")
            while True:
                time.sleep(10)
                stats = monitor.get_statistics()
                print(f"Statistiques: {stats['connections_checked']} connexions vérifiées, {stats['alerts_last_hour']} alertes")
        except KeyboardInterrupt:
            print("\nArrêt...")
            monitor.stop_monitoring()
    else:
        print("Impossible de démarrer la surveillance")
