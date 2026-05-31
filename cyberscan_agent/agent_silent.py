#!/usr/bin/env python3
"""
CyberScan Silent Agent - Agent silencieux pour surveillance en arrière-plan
Fonctionne complètement en arrière-plan sans interface ni console.
Stocke les informations dans des fichiers et les envoie au serveur.
"""

import asyncio
import websockets
import ssl
import json
import logging
import platform
import socket
import uuid
import os
import base64
import concurrent.futures
import sys
import time
import ctypes
import subprocess
import threading
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from datetime import datetime
import tempfile
import stat

# Configuration silencieuse - PAS DE LOGS CONSOLE
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Mode silencieux par défaut
SILENT_MODE = True
INSTALL_MODE = '--install' in sys.argv
UNINSTALL_MODE = '--uninstall' in sys.argv
SERVICE_MODE = '--service' in sys.argv

# Dossier de données silencieux (caché)
DATA_DIR = os.path.join(tempfile.gettempdir(), '.cyberscan_agent')
os.makedirs(DATA_DIR, exist_ok=True)

# Fichiers de données
SYSTEM_INFO_FILE = os.path.join(DATA_DIR, 'system_info.json')
SCAN_RESULTS_FILE = os.path.join(DATA_DIR, 'scan_results.json')
LOG_FILE = os.path.join(DATA_DIR, 'agent.log')
PID_FILE = os.path.join(DATA_DIR, 'agent.pid')

# Pool de threads pour les scans
scan_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

def hide_console():
    """Cache la console Windows."""
    try:
        import win32gui
        import win32con
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
    except:
        # Alternative avec ctypes
        try:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass

def set_file_readonly(filepath):
    """Définit un fichier en lecture seule."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except:
        pass

def make_file_writable(filepath):
    """Rend un fichier inscriptible avant écriture."""
    try:
        if os.path.exists(filepath):
            os.chmod(filepath, stat.S_IWUSR | stat.S_IRUSR)
    except:
        pass

def is_admin():
    """Vérifie si le script s'exécute avec des droits administratifs."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def add_to_startup():
    """Ajoute l'agent au démarrage de Windows en mode silencieux."""
    try:
        import winreg
        
        # Chemin de l'exécutable actuel
        if hasattr(sys, 'frozen'):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(__file__)
        
        # Clé de registre pour le démarrage
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        # Ajouter l'agent au démarrage en mode silencieux
        winreg.SetValueEx(key, "CyberScanAgent", 0, winreg.REG_SZ, f'"{exe_path}" --silent')
        winreg.CloseKey(key)
        
        return True
        
    except Exception as e:
        logger.error(f"Erreur ajout au démarrage: {e}")
        return False

def remove_from_startup():
    """Supprime l'agent du démarrage de Windows."""
    try:
        import winreg
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        try:
            winreg.DeleteValue(key, "CyberScanAgent")
            return True
        except FileNotFoundError:
            return True
        finally:
            winreg.CloseKey(key)
            
    except Exception as e:
        logger.error(f"Erreur suppression du démarrage: {e}")
        return False

def save_pid():
    """Sauvegarde le PID du processus."""
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        set_file_readonly(PID_FILE)
    except:
        pass

def remove_pid():
    """Supprime le fichier PID."""
    try:
        if os.path.exists(PID_FILE):
            os.chmod(PID_FILE, stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            os.remove(PID_FILE)
    except:
        pass

def is_already_running():
    """Vérifie si l'agent est déjà en cours d'exécution (compatible Windows)."""
    try:
        if not os.path.exists(PID_FILE):
            return False
        
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        
        # Sur Windows, utiliser psutil ou tasklist pour vérifier le PID
        try:
            import psutil
            return psutil.pid_exists(pid)
        except ImportError:
            # Fallback: vérifier via tasklist
            try:
                output = subprocess.check_output(
                    ['tasklist', '/FI', f'PID eq {pid}'],
                    stderr=subprocess.DEVNULL, text=True
                )
                return str(pid) in output
            except Exception:
                remove_pid()
                return False
    except:
        return False

class CyberScanListener(ServiceListener):
    def __init__(self):
        self.found_ip = None
        self.found_port = None
        self.event = threading.Event()

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            self.found_ip = socket.inet_ntoa(info.addresses[0])
            self.found_port = info.port
            self.event.set()

def discover_server():
    """Découverte automatique du serveur via mDNS."""
    try:
        zeroconf = Zeroconf()
        listener = CyberScanListener()
        browser = ServiceBrowser(zeroconf, "_cyberscan._tcp.local.", listener)
        
        listener.event.wait(timeout=10)
        
        zeroconf.close()
        
        if listener.found_ip:
            return listener.found_ip, listener.found_port
        else:
            return 'localhost', 8765
    except:
        return 'localhost', 8765

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()

def get_system_info():
    """Récupère les informations système complètes."""
    info = {
        'action': 'register',
        'agent_id': str(uuid.getnode()),
        'os': platform.system(),
        'hostname': socket.gethostname(),
        'local_ip': get_local_ip(),
        'is_admin': is_admin(),
        'python_version': platform.python_version(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor(),
        'platform': platform.platform(),
        'timestamp': datetime.now().isoformat(),
        'silent_mode': True
    }
    
    # Ajouter des informations supplémentaires si admin
    if is_admin():
        try:
            import psutil
            info.update({
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': {disk.mountpoint: psutil.disk_usage(disk.mountpoint).total 
                             for disk in psutil.disk_partitions()},
                'boot_time': psutil.boot_time(),
                'processes': len(psutil.pids())
            })
        except:
            pass
    
    # Sauvegarder les informations système
    try:
        make_file_writable(SYSTEM_INFO_FILE)
        with open(SYSTEM_INFO_FILE, 'w') as f:
            json.dump(info, f, indent=2)
        set_file_readonly(SYSTEM_INFO_FILE)
    except:
        pass
    
    return info

def run_scan_sync():
    """Exécute le scan système en arrière-plan."""
    try:
        # Import du module de scan
        import win_scanner
        scan_result = win_scanner.run_all_scans()
        
        # Ajouter des métadonnées
        scan_result['timestamp'] = datetime.now().isoformat()
        scan_result['agent_id'] = str(uuid.getnode())
        scan_result['scan_type'] = 'background'
        
        # Sauvegarder les résultats du scan
        try:
            make_file_writable(SCAN_RESULTS_FILE)
            with open(SCAN_RESULTS_FILE, 'w') as f:
                json.dump(scan_result, f, indent=2)
            set_file_readonly(SCAN_RESULTS_FILE)
        except:
            pass
        
        return scan_result
        
    except Exception as e:
        logger.error(f"Erreur scan: {e}")
        return {'error': str(e), 'timestamp': datetime.now().isoformat()}

def check_emails_hibp(emails, api_key):
    """Vérifie les emails via l'API HaveIBeenPwned."""
    try:
        import urllib.request
        import urllib.parse
        import hashlib
        
        results = []
        for email in emails:
            try:
                # SHA-1 hash de l'email
                sha1 = hashlib.sha1(email.lower().encode()).hexdigest()
                prefix, suffix = sha1[:5], sha1[5:]
                
                # Appel API HIBP
                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                req = urllib.request.Request(url)
                req.add_header('hibp-api-key', api_key)
                
                with urllib.request.urlopen(req) as response:
                    data = response.read().decode()
                    
                    # Vérifier si le suffix est présent
                    if suffix.upper() in data:
                        results.append({'email': email, 'pwned': True})
                    else:
                        results.append({'email': email, 'pwned': False})
                        
            except Exception as e:
                results.append({'email': email, 'error': str(e)})
        
        return results
    except Exception as e:
        logger.error(f"Erreur HIBP: {e}")
        return [{'error': str(e)}]

async def agent_loop():
    """Boucle principale de l'agent silencieux."""
    SERVER_IP, SERVER_PORT = discover_server()
    SERVER_URI = f"wss://{SERVER_IP}:{SERVER_PORT}"
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    retry_count = 0
    max_retries = 50  # Beaucoup de tentatives pour le mode silencieux
    retry_delay = 15  # Délai initial entre les tentatives
    
    while retry_count < max_retries:
        try:
            # Connexion au serveur
            async with websockets.connect(
                SERVER_URI, ssl=ssl_context,
                open_timeout=15, close_timeout=10,
                ping_interval=20, ping_timeout=60
            ) as websocket:
                # Envoyer les informations système
                system_info = get_system_info()
                await websocket.send(json.dumps(system_info))
                
                retry_count = 0  # Réinitialiser le compteur en cas de succès
                retry_delay = 15  # Réinitialiser le délai
                
                # Boucle de communication silencieuse
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        action = data.get('action', '')
                        
                        if action == 'scan':
                            # Signaler le début du scan
                            await websocket.send(json.dumps({
                                'action': 'scan_status',
                                'status': 'scanning'
                            }))
                            
                            # Exécuter le scan en arrière-plan
                            future = scan_executor.submit(run_scan_sync)
                            scan_result = future.result()
                            
                            # Signaler la fin du scan
                            await websocket.send(json.dumps({
                                'action': 'scan_status',
                                'status': 'idle'
                            }))
                            
                            # Envoyer les résultats (clé 'data' attendue par le serveur)
                            await websocket.send(json.dumps({
                                'action': 'scan_result',
                                'data': scan_result
                            }))
                        
                        elif action == 'check_emails':
                            emails = data.get('emails', [])
                            api_key = data.get('api_key', '')
                            
                            if emails and api_key:
                                hibp_result = check_emails_hibp(emails, api_key)
                                await websocket.send(json.dumps({
                                    'action': 'email_check_result',
                                    'results': hibp_result
                                }))
                        
                        elif action == 'deliver_pdf':
                            # Sauvegarder le PDF sur le bureau de l'utilisateur
                            try:
                                pdf_b64 = data.get('pdf_base64', '')
                                filename = data.get('filename', 'CyberScan_Rapport.pdf')
                                if pdf_b64:
                                    desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
                                    if not os.path.exists(desktop):
                                        desktop = os.path.expanduser('~')
                                    pdf_path = os.path.join(desktop, filename)
                                    with open(pdf_path, 'wb') as f:
                                        f.write(base64.b64decode(pdf_b64))
                                    await websocket.send(json.dumps({
                                        'action': 'pdf_delivered',
                                        'path': pdf_path
                                    }))
                            except Exception as e:
                                logger.error(f"Erreur sauvegarde PDF: {e}")
                        
                        elif action == 'ping':
                            await websocket.send(json.dumps({'action': 'pong', 'silent': True}))
                        
                        elif action == 'shutdown':
                            break
                            
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Erreur traitement message: {e}")
                        continue
                
        except Exception as e:
            retry_count += 1
            logger.error(f"Erreur connexion (tentative {retry_count}/{max_retries}): {e}")
            
            if retry_count < max_retries:
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 1.5, 300)  # Augmenter le délai jusqu'à 5 minutes

def run_silent():
    """Fonction principale en mode silencieux."""
    # Cacher la console immédiatement
    hide_console()
    
    # Vérifier si déjà en cours d'exécution
    if is_already_running():
        return  # Quitter silencieusement si déjà en cours
    
    # Sauvegarder le PID
    save_pid()
    
    try:
        # Lancer la boucle de l'agent
        asyncio.run(agent_loop())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Erreur critique: {e}")
    finally:
        # Nettoyer le fichier PID
        remove_pid()

def print_help():
    """Affiche l'aide."""
    help_text = """
CyberScan Silent Agent v2.1 - Agent silencieux d'arrière-plan

OPTIONS:
  --silent          Mode silencieux (par défaut, pas d'interface)
  --install         Installe l'agent au démarrage de Windows
  --uninstall       Supprime l'agent du démarrage de Windows
  --service         Mode service Windows
  --help            Affiche cette aide

CARACTÉRISTIQUES:
• Fonctionne complètement en arrière-plan
• Pas d'interface ni console visible
• Stocke les données dans des fichiers temporaires
• Communication silencieuse avec le serveur
• Installation automatique au démarrage

UTILISATION:
  CyberScanAgent.exe --install    # Installation silencieuse
  CyberScanAgent.exe              # Lancement silencieux
"""
    print(help_text)

def main():
    """Fonction principale."""
    
    # Gestion des arguments
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        return
    
    # Installation/Désinstallation
    if INSTALL_MODE:
        if not is_admin():
            # Redémarrer avec droits admin
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            return
        
        if add_to_startup():
            print("✅ CyberScan Silent Agent installé au démarrage")
        else:
            print("❌ Erreur lors de l'installation")
        return
    
    if UNINSTALL_MODE:
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            return
        
        if remove_from_startup():
            print("✅ CyberScan Silent Agent supprimé du démarrage")
        else:
            print("❌ Erreur lors de la suppression")
        return
    
    # Lancer l'agent silencieux (mode silencieux par défaut)
    run_silent()

if __name__ == "__main__":
    main()
