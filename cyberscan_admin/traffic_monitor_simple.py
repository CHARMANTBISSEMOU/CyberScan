"""
CyberScan Traffic Monitor (Version Simplifiée)
Module de surveillance de trafic réseau utilisant psutil.
Fiable et fonctionnel sans dépendances complexes.
"""

import threading
import time
import sqlite3
import logging
import json
import socket
import psutil
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Configuration
PACKET_BUFFER_SIZE = 10000
FLOW_TIMEOUT = 300
ALERT_THRESHOLD_CONNECTIONS = 100
PACKET_RETENTION_DAYS = 30

# Ports suspects
SUSPICIOUS_PORTS = {
    'IRC': [6667, 6668, 6669],
    'BitTorrent': [6881, 6882, 6883, 6884, 6885],
    'Backdoors': [1337, 31337, 12345],
    'Proxies': [8080, 3128, 1080],
    'Remote Access': [3389, 5900, 22]
}

# Processus suspects
SUSPICIOUS_PROCESSES = [
    'torrent', 'utorrent', 'bittorrent', 'emule', 'limewire',
    'tor', 'proxy', 'vpn', 'putty', 'teamviewer'
]

class TrafficMonitorSimple:
    def __init__(self, db_path="cyberscan.db"):
        self.db_path = db_path
        self.running = False
        self.monitor_thread = None
        self.alerts_callback = None
        self.logger = logging.getLogger(__name__)
        
        # Statistiques
        self.statistics = defaultdict(int)
        self.connection_history = deque(maxlen=1000)
        self.previous_connections = set()
        
        # Initialiser la base de données
        self._init_database()
    
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
                    status TEXT,
                    process_name TEXT,
                    pid INTEGER,
                    risk_score INTEGER DEFAULT 0,
                    is_suspicious BOOLEAN DEFAULT 0,
                    is_external BOOLEAN DEFAULT 0
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
                    total_connections INTEGER DEFAULT 0,
                    external_connections INTEGER DEFAULT 0,
                    suspicious_connections INTEGER DEFAULT 0,
                    alert_count INTEGER DEFAULT 0
                )
            ''')
            
            # Index
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON network_connections(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_flow_start ON traffic_flows(start_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON traffic_alerts(timestamp)')
            
            conn.commit()
            self.logger.info("Base de données de trafic initialisée")
    
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
    
    def _get_process_name(self, pid):
        """Obtient le nom du processus depuis son PID."""
        try:
            if pid == 0:
                return "System"
            process = psutil.Process(pid)
            return process.name()
        except:
            return "Unknown"
    
    def _calculate_risk_score(self, connection):
        """Calcule un score de risque pour une connexion."""
        score = 0
        reasons = []
        
        try:
            # Connexion vers l'extérieur
            if connection.get('is_external', False):
                score += 1
                reasons.append("external_connection")
            
            # Ports suspects
            remote_port = connection.get('remote_port', 0)
            for threat_type, ports in SUSPICIOUS_PORTS.items():
                if remote_port in ports:
                    score += 2
                    reasons.append(f"{threat_type}_port")
                    break
            
            # Processus suspects
            process_name = connection.get('process_name', '').lower()
            for sus_proc in SUSPICIOUS_PROCESSES:
                if sus_proc in process_name:
                    score += 3
                    reasons.append(f"suspicious_process_{sus_proc}")
                    break
            
            # État de connexion
            if connection.get('status') == 'ESTABLISHED' and connection.get('is_external', False):
                score += 1
                reasons.append("established_external")
            
            # Connexions sortantes sur ports hauts (souvent P2P)
            if remote_port > 10000 and connection.get('is_external', False):
                score += 1
                reasons.append("high_port_external")
            
        except Exception as e:
            self.logger.warning(f"Erreur calcul risque: {e}")
        
        return min(score, 10), reasons
    
    def _get_network_connections(self):
        """Récupère les connexions réseau via psutil."""
        connections = []
        
        try:
            # Récupérer toutes les connexions Internet
            psutil_connections = psutil.net_connections(kind='inet')
            
            for conn in psutil_connections:
                # Ignorer les connexions sans adresse locale
                if not conn.laddr:
                    continue
                
                # Extraire les informations
                local_ip = conn.laddr.ip
                local_port = conn.laddr.port
                
                remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                remote_port = conn.raddr.port if conn.raddr else 0
                
                # Déterminer le protocole
                protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                
                # Vérifier si c'est une connexion externe
                is_external = self._is_local_ip(local_ip) and not self._is_local_ip(remote_ip)
                
                # Créer l'objet connexion
                connection = {
                    'protocol': protocol,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'status': conn.status,
                    'pid': conn.pid,
                    'is_external': is_external,
                    'timestamp': datetime.now()
                }
                
                # Ajouter le nom du processus
                if conn.pid:
                    connection['process_name'] = self._get_process_name(conn.pid)
                else:
                    connection['process_name'] = 'Unknown'
                
                connections.append(connection)
        
        except Exception as e:
            self.logger.warning(f"Erreur récupération connexions: {e}")
        
        return connections
    
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
                     status, process_name, pid, risk_score, is_suspicious, is_external)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (connection['protocol'], connection['local_ip'], connection['local_port'],
                      connection['remote_ip'], connection['remote_port'], connection['status'],
                      connection.get('process_name'), connection.get('pid'),
                      connection['risk_score'], connection['is_suspicious'], connection['is_external']))
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
            
            elif any('suspicious_process' in reason for reason in risk_reasons):
                alert_type = 'suspicious_process_detected'
                severity = 'medium'
                details['process'] = connection.get('process_name')
            
            elif any('backdoor' in reason for reason in risk_reasons):
                alert_type = 'potential_backdoor'
                severity = 'high'
                details['port'] = connection['remote_port']
            
            elif any('irc' in reason for reason in risk_reasons):
                alert_type = 'irc_activity_detected'
                severity = 'medium'
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
    
    def _monitor_loop(self):
        """Boucle principale de surveillance."""
        self.logger.info("Démarrage surveillance réseau")
        
        while self.running:
            try:
                # Récupérer les connexions
                connections = self._get_network_connections()
                
                # Analyser chaque connexion
                for conn in connections:
                    self._analyze_connection(conn)
                
                # Mettre à jour les statistiques
                self.statistics['connections_checked'] = len(connections)
                self.statistics['monitoring_cycles'] += 1
                
                # Statistiques pour ce cycle
                external_count = sum(1 for c in connections if c.get('is_external', False))
                suspicious_count = sum(1 for c in connections if c.get('is_suspicious', False))
                
                self.statistics['external_connections'] = external_count
                self.statistics['suspicious_connections'] = suspicious_count
                
                # Stocker les statistiques
                self._store_statistics(len(connections), external_count, suspicious_count)
                
                # Nettoyer les anciennes données périodiquement
                if self.statistics['monitoring_cycles'] % 60 == 0:  # Toutes les 5 minutes
                    self._cleanup_old_data()
                
                # Attendre avant le prochain cycle
                time.sleep(5)  # Vérifier toutes les 5 secondes
                
            except Exception as e:
                self.logger.error(f"Erreur dans boucle de surveillance: {e}")
                time.sleep(5)
        
        self.logger.info("Surveillance réseau arrêtée")
    
    def _store_statistics(self, total_conn, external_conn, suspicious_conn):
        """Stocke les statistiques de trafic."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO traffic_statistics 
                    (total_connections, external_connections, suspicious_connections)
                    VALUES (?, ?, ?)
                ''', (total_conn, external_conn, suspicious_conn))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Erreur stockage statistiques: {e}")
    
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
                
                # Supprimer les anciennes statistiques
                cursor.execute("DELETE FROM traffic_statistics WHERE timestamp < ?", (cutoff_date,))
                deleted_stats = cursor.rowcount
                
                conn.commit()
                
                if deleted_connections > 0 or deleted_alerts > 0 or deleted_stats > 0:
                    self.logger.info(f"Nettoyage: {deleted_connections} connexions, {deleted_alerts} alertes, {deleted_stats} stats supprimées")
                    
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
            
            # Statistiques agrégées
            cursor.execute('''
                SELECT SUM(total_connections), SUM(external_connections), SUM(suspicious_connections)
                FROM traffic_statistics 
                WHERE timestamp > datetime('now', '-1 hour')
            ''')
            result = cursor.fetchone()
            if result[0]:
                stats['total_connections_hour'] = result[0]
                stats['external_connections_hour'] = result[1] or 0
                stats['suspicious_connections_hour'] = result[2] or 0
        
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
        print(f'🚨 ALERTE: {alert["type"]} - {alert["local_ip"]} -> {alert["remote_ip"]}')
        print(f'   Protocole: {alert["protocol"]}, Processus: {alert.get("process_name", "Unknown")}')
        print(f'   Détails: {alert["details"]}')
    
    monitor = TrafficMonitorSimple()
    
    if monitor.start_monitoring(on_alert):
        try:
            print("Surveillance en cours... Appuyez sur Ctrl+C pour arrêter.")
            while True:
                time.sleep(10)
                stats = monitor.get_statistics()
                print(f"Statistiques: {stats.get('connections_checked', 0)} connexions, {stats.get('external_connections', 0)} externes, {stats.get('suspicious_connections', 0)} suspectes")
        except KeyboardInterrupt:
            print("\nArrêt...")
            monitor.stop_monitoring()
    else:
        print("Impossible de démarrer la surveillance")
