import sqlite3
import os
import json
import logging
from datetime import datetime
from crypto_utils import encrypt_data, decrypt_data

class CyberScanDB:
    def __init__(self, db_path=None):
        if db_path is None or db_path == "cyberscan.db":
            appdata = os.environ.get('APPDATA', '')
            if appdata:
                app_dir = os.path.join(appdata, 'CyberScan')
                os.makedirs(app_dir, exist_ok=True)
                self.db_path = os.path.join(app_dir, "cyberscan.db")
            else:
                self.db_path = "cyberscan.db"
        else:
            self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS machines (
                    id TEXT PRIMARY KEY,
                    hostname TEXT,
                    ip_address TEXT,
                    os_name TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    last_score INTEGER,
                    status TEXT
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_id TEXT,
                    timestamp DATETIME,
                    score INTEGER,
                    json_data TEXT,
                    FOREIGN KEY(machine_id) REFERENCES machines(id)
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    provider TEXT PRIMARY KEY,
                    key_value TEXT
                )
            ''')
            # Table de paramètres généraux (config alertes, etc.)
            c.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            conn.commit()

    def register_machine(self, agent_id, hostname, os_name, ip_address=None):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            
            # Logique pour éviter les doublons entre le scan réseau (unmanaged) et les vrais agents
            if agent_id.startswith("unmanaged_"):
                # Si c'est un agent non géré, on vérifie si l'IP n'appartient pas déjà à un agent géré
                c.execute("SELECT id FROM machines WHERE ip_address = ? AND id NOT LIKE 'unmanaged_%'", (ip_address,))
                if c.fetchone() is not None:
                    return # On ignore l'ajout
            else:
                # Si c'est un vrai agent, on supprime tout agent non géré avec la même IP
                if ip_address:
                    c.execute("DELETE FROM machines WHERE ip_address = ? AND id LIKE 'unmanaged_%'", (ip_address,))
            
            c.execute("SELECT id FROM machines WHERE id = ?", (agent_id,))
            if c.fetchone() is None:
                c.execute('''
                    INSERT INTO machines (id, hostname, ip_address, os_name, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'online')
                ''', (agent_id, hostname, ip_address, os_name, now, now))
            else:
                c.execute('''
                    UPDATE machines 
                    SET hostname = ?, ip_address = ?, os_name = ?, last_seen = ?, status = 'online'
                    WHERE id = ?
                ''', (hostname, ip_address, os_name, now, agent_id))
            conn.commit()

    def update_machine_status(self, agent_id, status):
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("UPDATE machines SET status = ? WHERE id = ?", (status, agent_id))
            conn.commit()

    def save_scan_result(self, agent_id, score, json_data):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO scans (machine_id, timestamp, score, json_data)
                VALUES (?, ?, ?, ?)
            ''', (agent_id, now, score, json.dumps(json_data)))
            # Ne pas écraser un bon score par 0 (échec IA): conserver le précédent
            if score and score > 0:
                c.execute('UPDATE machines SET last_score = ? WHERE id = ?', (score, agent_id))
            else:
                c.execute('SELECT last_score FROM machines WHERE id = ?', (agent_id,))
                row = c.fetchone()
                if not row or row[0] is None:
                    c.execute('UPDATE machines SET last_score = ? WHERE id = ?', (score, agent_id))
            conn.commit()

    def heartbeat(self, agent_id):
        """Met à jour last_seen pour un agent connecté (appelé sur ping/pong/messages)."""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("UPDATE machines SET last_seen = ?, status = 'online' WHERE id = ?", (now, agent_id))
            conn.commit()

    def get_all_machines(self, max_age_days=30):
        """
        Récupère toutes les machines vues dans les max_age_days derniers jours.
        Ne supprime plus les machines - les marque juste 'offline' si pas vues récemment.
        """
        from datetime import timedelta
        cutoff_date = (datetime.now() - timedelta(days=max_age_days)).strftime('%Y-%m-%d %H:%M:%S')
        
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            
            # Marquer comme offline les machines non vues depuis max_age_days
            c.execute("""
                UPDATE machines 
                SET status = 'offline' 
                WHERE last_seen < ? AND status = 'online'
            """, (cutoff_date,))
            
            # Dédoublonnage conservateur: garder l'entrée avec le meilleur score/historique
            # Uniquement si même IP ET même hostname (éviter faux positifs)
            c.execute('''
                DELETE FROM machines 
                WHERE rowid NOT IN (
                    SELECT MAX(rowid) 
                    FROM machines 
                    GROUP BY COALESCE(ip_address, ''), COALESCE(hostname, '')
                    HAVING ip_address IS NOT NULL OR hostname IS NOT NULL
                )
            ''')
            
            conn.commit()

            conn.row_factory = sqlite3.Row
            c2 = conn.cursor()
            # Retourner toutes les machines, même offline (pour l'historique)
            c2.execute("SELECT * FROM machines ORDER BY last_seen DESC")
            return [dict(row) for row in c2.fetchall()]
    
    def cleanup_old_machines(self, max_age_days=30):
        """
        Supprime définitivement les machines non vues depuis plus de max_age_days.
        À appeler périodiquement (ex: une fois par jour), pas à chaque requête.
        """
        from datetime import timedelta
        cutoff_date = (datetime.now() - timedelta(days=max_age_days)).strftime('%Y-%m-%d %H:%M:%S')
        
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM machines WHERE last_seen < ?", (cutoff_date,))
            deleted = c.rowcount
            conn.commit()
            if deleted > 0:
                logging.info(f"Nettoyage: {deleted} machine(s) supprimée(s) (non vues depuis {max_age_days}j)")
            return deleted

    def get_active_machines(self):
        """Retourne uniquement les machines actuellement connectées (status = 'online')"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM machines WHERE status = 'online'")
            return [dict(row) for row in c.fetchall()]

    def get_latest_scan(self, agent_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM scans WHERE machine_id = ? ORDER BY timestamp DESC LIMIT 1", (agent_id,))
            row = c.fetchone()
            if row:
                return dict(row)
            return None

    def set_api_key(self, provider, key_value):
        """Enregistre une clé API de manière chiffrée."""
        try:
            # Chiffrer la clé avant stockage
            encrypted_key = encrypt_data(key_value)
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO api_keys (provider, key_value) VALUES (?, ?)
                    ON CONFLICT(provider) DO UPDATE SET key_value=excluded.key_value
                ''', (provider, encrypted_key))
                conn.commit()
        except Exception as e:
            logging.error(f"Erreur enregistrement clé API {provider}: {e}")

    def get_setting(self, key):
        """Récupère un paramètre général (ex: alert_config)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT value FROM settings WHERE key = ?", (key,))
                row = c.fetchone()
                if row:
                    return row[0]
                return None
        except Exception as e:
            logging.error(f"Erreur récupération paramètre {key}: {e}")
            return None

    def set_setting(self, key, value):
        """Enregistre un paramètre général."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO settings (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value
                ''', (key, value))
                conn.commit()
        except Exception as e:
            logging.error(f"Erreur sauvegarde paramètre {key}: {e}")

    def get_api_key(self, provider):
        """Récupère une clé API et la déchiffre."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT key_value FROM api_keys WHERE provider = ?", (provider,))
                row = c.fetchone()
                if row and row[0]:
                    # Déchiffrer la clé
                    decrypted = decrypt_data(row[0])
                    return decrypted
                return None
        except Exception as e:
            logging.error(f"Erreur récupération clé API {provider}: {e}")
            return None
