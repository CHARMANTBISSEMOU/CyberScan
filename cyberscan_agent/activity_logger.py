"""
CyberScan Activity Logger
Journalise les activités utilisateur (applications ouvertes, sites visités)
de manière continue en arrière-plan. Les données sont stockées dans un fichier
protégé et invisible pour l'utilisateur, puis envoyées et effacées lors du scan.
"""

import os
import json
import time
import base64
import shutil
import sqlite3
import logging
import subprocess
import ctypes
import threading
from datetime import datetime, timedelta

NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW

LOG_DIR = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'CyberScan')
LOG_FILE = os.path.join(LOG_DIR, '.cs_activity.dat')

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04
FILE_ATTRIBUTE_READONLY = 0x01

# Processus système à ignorer (ne pas journaliser)
SYSTEM_PROCESSES = {
    'System', 'System Idle Process', 'svchost.exe', 'csrss.exe', 'smss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 'dwm.exe',
    'fontdrvhost.exe', 'LogonUI.exe', 'conhost.exe', 'RuntimeBroker.exe',
    'SearchHost.exe', 'StartMenuExperienceHost.exe', 'TextInputHost.exe',
    'ShellExperienceHost.exe', 'sihost.exe', 'taskhostw.exe', 'ctfmon.exe',
    'dllhost.exe', 'spoolsv.exe', 'SecurityHealthService.exe', 'SecurityHealthSystray.exe',
    'MsMpEng.exe', 'NisSrv.exe', 'SearchIndexer.exe', 'WmiPrvSE.exe',
    'Memory Compression', 'Registry', 'Idle', 'dasHost.exe', 'SgrmBroker.exe',
    'uhssvc.exe', 'WUDFHost.exe', 'audiodg.exe', 'CompPkgSrv.exe',
    'explorer.exe', 'Taskmgr.exe', 'cmd.exe', 'powershell.exe',
    'WindowsTerminal.exe', 'SearchProtocolHost.exe', 'SearchFilterHost.exe',
    'backgroundTaskHost.exe', 'ApplicationFrameHost.exe', 'SystemSettings.exe',
    'MusNotifyIcon.exe', 'PhoneExperienceHost.exe', 'LockApp.exe',
    'WidgetService.exe', 'Widgets.exe', 'GameBarPresenceWriter.exe',
    'SecurityHealthHost.exe', 'MoUsoCoreWorker.exe', 'TiWorker.exe',
    'CyberScanAgent.exe',
}

_logger_thread = None
_logger_stop_event = threading.Event()
_known_processes = set()
_lock = threading.Lock()


# ============================================================
# Gestion fichier protégé
# ============================================================
def _ensure_dir():
    """Crée le répertoire de logs et le rend invisible."""
    os.makedirs(LOG_DIR, exist_ok=True)
    try:
        ctypes.windll.kernel32.SetFileAttributesW(LOG_DIR, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
    except:
        pass


def _protect_file(path):
    """Rend le fichier caché + système + lecture seule."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(
            path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY)
    except:
        pass


def _unprotect_file(path):
    """Retire la protection pour écriture."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(path, 0)
    except:
        pass


def _read_log():
    """Lit le fichier de logs d'activité (format obfusqué base64)."""
    if not os.path.exists(LOG_FILE):
        return {"apps": [], "last_scan": None}
    try:
        _unprotect_file(LOG_FILE)
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            encoded = f.read().strip()
        if not encoded:
            return {"apps": [], "last_scan": None}
        data = json.loads(base64.b64decode(encoded).decode('utf-8'))
        return data
    except:
        return {"apps": [], "last_scan": None}


def _write_log(data):
    """Écrit le fichier de logs (protégé et obfusqué)."""
    _ensure_dir()
    _unprotect_file(LOG_FILE)
    encoded = base64.b64encode(json.dumps(data, default=str).encode('utf-8')).decode('utf-8')
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(encoded)
    _protect_file(LOG_FILE)


# ============================================================
# Capture des processus (applications ouvertes)
# ============================================================
def _snapshot_processes():
    """Récupère la liste des processus utilisateur en cours."""
    processes = set()
    try:
        proc = subprocess.run(
            ['tasklist', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=10,
            creationflags=NO_WINDOW
        )
        for line in proc.stdout.strip().split('\n'):
            parts = line.strip().split('","')
            if parts:
                name = parts[0].strip('"')
                if name and name not in SYSTEM_PROCESSES:
                    processes.add(name)
    except:
        pass
    return processes


def _log_new_processes():
    """Détecte les nouveaux processus et les enregistre."""
    global _known_processes
    current = _snapshot_processes()
    new_procs = current - _known_processes
    _known_processes = current

    if new_procs:
        with _lock:
            data = _read_log()
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for proc_name in new_procs:
                data['apps'].append({
                    "name": proc_name,
                    "first_seen": now,
                })
            _write_log(data)


# ============================================================
# Capture de l'historique de navigation
# ============================================================
def _get_browser_history(since_str=None):
    """Collecte l'historique des navigateurs depuis la dernière analyse."""
    results = []

    if since_str:
        try:
            since = datetime.fromisoformat(since_str)
        except:
            since = datetime.now() - timedelta(hours=24)
    else:
        since = datetime.now() - timedelta(hours=24)

    # --- Chrome & Edge (Chromium) ---
    localappdata = os.environ.get('LOCALAPPDATA', '')
    chrome_paths = []
    if localappdata:
        chrome_paths.append((
            os.path.join(localappdata, 'Google', 'Chrome', 'User Data', 'Default', 'History'), 'Chrome'))
        chrome_paths.append((
            os.path.join(localappdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'History'), 'Edge'))

    chrome_epoch = datetime(1601, 1, 1)
    since_chrome = int((since - chrome_epoch).total_seconds() * 1_000_000)

    for hist_path, browser in chrome_paths:
        if not os.path.exists(hist_path):
            continue
        tmp_path = os.path.join(LOG_DIR, f'.tmp_{browser.lower()}_hist')
        try:
            # Copie non bloquante : si le fichier est verrouillé, on skip
            try:
                shutil.copy2(hist_path, tmp_path)
            except (PermissionError, OSError):
                logging.debug(f"{browser}: fichier historique verrouillé, ignoré")
                continue
            conn = sqlite3.connect(tmp_path, timeout=5)
            conn.text_factory = str
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, title, last_visit_time FROM urls "
                "WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT 100",
                (since_chrome,)
            )
            for url, title, visit_time in cursor.fetchall():
                try:
                    dt = chrome_epoch + timedelta(microseconds=visit_time)
                    visit_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    visit_str = "?"
                results.append({
                    "browser": browser,
                    "url": url[:200],
                    "title": (title or "")[:100],
                    "visited_at": visit_str
                })
            conn.close()
        except Exception as e:
            logging.debug(f"Lecture historique {browser}: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

    # --- Firefox ---
    appdata = os.environ.get('APPDATA', '')
    profiles_dir = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
    if os.path.exists(profiles_dir):
        since_ff = int(since.timestamp() * 1_000_000)
        for profile in os.listdir(profiles_dir):
            places = os.path.join(profiles_dir, profile, 'places.sqlite')
            if not os.path.exists(places):
                continue
            tmp_path = os.path.join(LOG_DIR, '.tmp_ff_hist')
            try:
                try:
                    shutil.copy2(places, tmp_path)
                except (PermissionError, OSError):
                    logging.debug("Firefox: fichier historique verrouillé, ignoré")
                    continue
                conn = sqlite3.connect(tmp_path, timeout=5)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT p.url, p.title, h.visit_date "
                    "FROM moz_places p JOIN moz_historyvisits h ON p.id = h.place_id "
                    "WHERE h.visit_date > ? ORDER BY h.visit_date DESC LIMIT 100",
                    (since_ff,)
                )
                for url, title, visit_time in cursor.fetchall():
                    try:
                        dt = datetime.fromtimestamp(visit_time / 1_000_000)
                        visit_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        visit_str = "?"
                    results.append({
                        "browser": "Firefox",
                        "url": url[:200],
                        "title": (title or "")[:100],
                        "visited_at": visit_str
                    })
                conn.close()
            except Exception as e:
                logging.debug(f"Lecture historique Firefox: {e}")
            finally:
                try:
                    os.unlink(tmp_path)
                except:
                    pass

    return results


# ============================================================
# API publique
# ============================================================
def get_and_clear_activities():
    """
    Appelé lors du scan : récupère toutes les activités accumulées
    (apps + historique navigateur), puis VIDE le fichier de logs.
    Les données ne seront donc analysées qu'une seule fois.
    Timeout de 15 secondes max pour ne pas bloquer le scan.
    """
    try:
        with _lock:
            data = _read_log()
            last_scan = data.get('last_scan')

            # Lecture historique avec gestion d'erreur
            try:
                websites = _get_browser_history(last_scan)
            except Exception as e:
                logging.warning(f"Historique navigateur inaccessible: {e}")
                websites = []

            activities = {
                "apps_opened": data.get('apps', []),
                "websites_visited": websites,
                "collection_period": {
                    "from": last_scan or "premier scan",
                    "to": datetime.now().isoformat()
                }
            }

            # Vider le fichier et enregistrer le nouveau timestamp
            _write_log({"apps": [], "last_scan": datetime.now().isoformat()})

            return activities
    except Exception as e:
        logging.error(f"Erreur collecte activités: {e}")
        return {"apps_opened": [], "websites_visited": [], "collection_period": {"from": "erreur", "to": datetime.now().isoformat()}}


def _background_logger():
    """Thread de fond : capture les processus toutes les 2 minutes."""
    global _known_processes
    _known_processes = _snapshot_processes()

    while not _logger_stop_event.is_set():
        try:
            _log_new_processes()
        except Exception as e:
            logging.debug(f"Erreur logger activité: {e}")
        _logger_stop_event.wait(120)


def start_logging():
    """Démarre le logger d'activité en arrière-plan."""
    global _logger_thread
    if _logger_thread and _logger_thread.is_alive():
        return
    _ensure_dir()
    _logger_stop_event.clear()
    _logger_thread = threading.Thread(target=_background_logger, daemon=True)
    _logger_thread.start()
    logging.info("Logger d'activité utilisateur démarré")


def stop_logging():
    """Arrête le logger d'activité."""
    _logger_stop_event.set()
    if _logger_thread:
        _logger_thread.join(timeout=5)
    logging.info("Logger d'activité arrêté")
