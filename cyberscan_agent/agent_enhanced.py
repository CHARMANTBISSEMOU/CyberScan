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
from ctypes import wintypes
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
import threading

# Mode silencieux pour le démarrage automatique
SILENT_MODE = '--silent' in sys.argv
INSTALL_MODE = '--install' in sys.argv
UNINSTALL_MODE = '--uninstall' in sys.argv

if SILENT_MODE:
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Vérification des droits administratifs
def is_admin():
    """Vérifie si le script s'exécute avec des droits administratifs."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_admin_privileges():
    """Demande des privilèges administratifs si nécessaire."""
    if not is_admin():
        logging.warning("Redémarrage avec droits administratifs...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

# Gestion du service Windows (lancement au démarrage)
def add_to_startup():
    """Ajoute l'agent au démarrage de Windows."""
    try:
        import winreg
        
        # Chemin de l'exécutable actuel
        exe_path = os.path.abspath(sys.executable if hasattr(sys, 'frozen') else __file__)
        
        # Clé de registre pour le démarrage
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        # Ajouter l'agent au démarrage (mode silencieux)
        winreg.SetValueEx(key, "CyberScanAgent", 0, winreg.REG_SZ, f'"{exe_path}" --silent')
        winreg.CloseKey(key)
        
        logging.info("✅ CyberScan Agent ajouté au démarrage de Windows")
        return True
        
    except Exception as e:
        logging.error(f"❌ Erreur ajout au démarrage: {e}")
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
            logging.info("✅ CyberScan Agent supprimé du démarrage de Windows")
            return True
        except FileNotFoundError:
            logging.info("ℹ️ CyberScan Agent n'était pas dans le démarrage")
            return True
        finally:
            winreg.CloseKey(key)
            
    except Exception as e:
        logging.error(f"❌ Erreur suppression du démarrage: {e}")
        return False

def check_startup_status():
    """Vérifie si l'agent est dans le démarrage de Windows."""
    try:
        import winreg
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ
        )
        
        try:
            value, _ = winreg.QueryValueEx(key, "CyberScanAgent")
            winreg.CloseKey(key)
            return True, value
        except FileNotFoundError:
            winreg.CloseKey(key)
            return False, None
            
    except Exception as e:
        logging.error(f"❌ Erreur vérification démarrage: {e}")
        return False, None

# Pool de threads pour exécuter les scans sans bloquer le WebSocket
scan_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

# Détection automatique du serveur sur le réseau local via mDNS (Zeroconf)

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
    """Découverte automatique du serveur via mDNS (Zeroconf)."""
    logging.info("Recherche du serveur CyberScan via mDNS (Zeroconf) sur le réseau local...")
    zeroconf = Zeroconf()
    listener = CyberScanListener()
    browser = ServiceBrowser(zeroconf, "_cyberscan._tcp.local.", listener)
    
    listener.event.wait(timeout=10)
    
    zeroconf.close()
    
    if listener.found_ip:
        logging.info(f"Serveur découvert via mDNS: {listener.found_ip}:{listener.found_port}")
        return listener.found_ip, listener.found_port
    else:
        logging.warning("Aucun serveur trouvé via mDNS.")
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
    """Récupère les informations système complètes avec droits admin."""
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
        'platform': platform.platform()
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
                'boot_time': psutil.boot_time()
            })
        except ImportError:
            pass
        except Exception as e:
            logging.warning(f"Impossible d'obtenir les infos système avancées: {e}")
    
    return info

def get_desktop_path():
    """Retourne le chemin du bureau de l'utilisateur courant."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        desktop = winreg.QueryValueEx(key, "Desktop")[0]
        winreg.CloseKey(key)
        return desktop
    except:
        return os.path.join(os.path.expanduser("~"), "Desktop")

def run_scan_sync(mode='full'):
    """Exécute le scan dans un thread séparé (ne bloque pas le WebSocket).
    
    Args:
        mode: 'full' pour scan complet, 'quick' pour scan rapide (< 20s)
    """
    import traceback as _tb
    try:
        import win_scanner
        return win_scanner.run_all_scans(mode=mode)
    except Exception as e:
        tb = _tb.format_exc()
        logging.error(f"Erreur lors du scan: {e}\n{tb}")
        return {'error': str(e), 'traceback': tb}

def check_emails_hibp(emails, api_key):
    """Vérifie les emails via l'API HaveIBeenPwned."""
    import urllib.request
    import urllib.parse
    
    results = []
    for email in emails:
        try:
            # SHA-1 hash de l'email
            import hashlib
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

def get_ssl_context():
    """
    Configure le contexte SSL de manière sécurisée.
    
    Priorité:
    1. Si certificat serveur présent localement (cert.pem) -> vérification stricte
    2. Sinon, vérification système (certificats Windows/Linux)
    3. En dernier recours uniquement: mode désactivé (développement)
    
    Variable d'environnement CYBERSCAN_INSECURE=1 pour désactiver la vérification (dev uniquement)
    """
    import os
    import sys
    
    # Mode développement/désactivé (uniquement si explicitement demandé)
    if os.environ.get('CYBERSCAN_INSECURE') == '1':
        logging.warning("⚠️  Mode SSL désactivé (CYBERSCAN_INSECURE=1) - Développement uniquement!")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
    
    # Chercher le certificat serveur dans plusieurs emplacements
    possible_cert_paths = []
    if getattr(sys, 'frozen', False):
        # Mode exécutable PyInstaller
        base_dir = os.path.dirname(sys.executable)
        possible_cert_paths.extend([
            os.path.join(base_dir, 'certs', 'cert.pem'),
            os.path.join(base_dir, 'cert.pem'),
        ])
    else:
        # Mode script Python
        script_dir = os.path.dirname(os.path.abspath(__file__))
        possible_cert_paths.extend([
            os.path.join(script_dir, '..', 'certs', 'cert.pem'),
            os.path.join(script_dir, 'certs', 'cert.pem'),
        ])
    
    # 1. Essayer avec un certificat local spécifique
    for cert_path in possible_cert_paths:
        if os.path.exists(cert_path):
            try:
                ssl_context.load_verify_locations(cert_path)
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                ssl_context.check_hostname = True
                logging.info(f"🔒 SSL: Vérification activée avec certificat local {cert_path}")
                return ssl_context
            except Exception as e:
                logging.warning(f"Impossible de charger le certificat {cert_path}: {e}")
    
    # 2. Utiliser les certificats système par défaut
    try:
        ssl_context.load_default_certs()
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.check_hostname = True
        logging.info("🔒 SSL: Vérification activée avec certificats système")
        return ssl_context
    except Exception as e:
        logging.warning(f"Impossible de charger les certificats système: {e}")
    
    # 3. Dernier recours: avertir et continuer (pour compatibilité legacy)
    logging.error("❌ ERREUR SSL: Aucun certificat trouvé. Connexion non sécurisée!")
    logging.error("   Pour la production, copiez le cert.pem du serveur dans le dossier certs/")
    logging.error("   Pour le développement uniquement: export CYBERSCAN_INSECURE=1")
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


async def agent_loop():
    """Boucle principale de l'agent."""
    global SERVER_IP, SERVER_PORT, SERVER_URI
    
    SERVER_IP, SERVER_PORT = discover_server()
    SERVER_URI = f"wss://{SERVER_IP}:{SERVER_PORT}"
    
    ssl_context = get_ssl_context()
    
    retry_count = 0
    max_retries = 5
    
    while retry_count < max_retries:
        try:
            logging.info(f"Tentative de connexion au serveur {SERVER_URI}...")
            
            async with websockets.connect(SERVER_URI, ssl=ssl_context) as websocket:
                logging.info("✅ Connecté au serveur CyberScan")
                
                # Envoyer les informations système
                system_info = get_system_info()
                await websocket.send(json.dumps(system_info))
                
                # Boucle de communication
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        
                        if data.get('action') == 'scan':
                            scan_mode = data.get('mode', 'full')
                            logging.info(f"🔍 Lancement du scan système (mode: {scan_mode})...")
                            
                            # Exécuter le scan dans un thread séparé avec le mode
                            future = scan_executor.submit(run_scan_sync, scan_mode)
                            scan_result = future.result()
                            
                            # Envoyer les résultats
                            await websocket.send(json.dumps({
                                'action': 'scan_result',
                                'data': scan_result
                            }))
                            
                        elif data.get('action') == 'hibp_check':
                            emails = data.get('emails', [])
                            api_key = data.get('api_key', '')
                            
                            if emails and api_key:
                                logging.info("🔍 Vérification des emails HIBP...")
                                hibp_result = check_emails_hibp(emails, api_key)
                                
                                await websocket.send(json.dumps({
                                    'action': 'hibp_result',
                                    'result': hibp_result
                                }))
                        
                        elif data.get('action') == 'ping':
                            await websocket.send(json.dumps({'action': 'pong'}))
                            
                    except json.JSONDecodeError:
                        logging.warning("Message JSON invalide reçu")
                    except Exception as e:
                        logging.error(f"Erreur traitement message: {e}")
                
                retry_count = 0  # Réinitialiser le compteur en cas de succès
                
        except Exception as e:
            retry_count += 1
            logging.error(f"Erreur de connexion (tentative {retry_count}/{max_retries}): {e}")
            
            if retry_count < max_retries:
                logging.info("Nouvelle tentative dans 30 secondes...")
                await asyncio.sleep(30)
            else:
                logging.error("❌ Nombre maximum de tentatives atteint")
                break

def print_help():
    """Affiche l'aide."""
    help_text = """
CyberScan Agent v2.0 - Usage

OPTIONS:
  --silent          Mode silencieux (pas de console visible)
  --install         Installe l'agent au démarrage de Windows
  --uninstall       Supprime l'agent du démarrage de Windows
  --status          Vérifie le statut de l'agent
  --help            Affiche cette aide

EXEMPLES:
  CyberScanAgent.exe                    Mode normal
  CyberScanAgent.exe --silent           Mode silencieux
  CyberScanAgent.exe --install          Installer au démarrage
  CyberScanAgent.exe --uninstall        Supprimer du démarrage
  CyberScanAgent.exe --status           Vérifier le statut

NOTE: L'agent nécessite des droits administratifs pour certaines fonctionnalités.
"""
    print(help_text)

def check_status():
    """Vérifie le statut de l'agent."""
    print("=== STATUT CYBERSCAN AGENT ===")
    
    # Vérifier les droits admin
    admin_status = "✅ Administrateur" if is_admin() else "⚠️ Utilisateur standard"
    print(f"Droits: {admin_status}")
    
    # Vérifier le démarrage
    in_startup, startup_path = check_startup_status()
    startup_status = "✅ Dans le démarrage" if in_startup else "❌ Pas dans le démarrage"
    print(f"Démarrage: {startup_status}")
    
    if startup_path:
        print(f"Chemin: {startup_path}")
    
    # Vérifier la connexion au serveur
    try:
        SERVER_IP, SERVER_PORT = discover_server()
        print(f"Serveur: {SERVER_IP}:{SERVER_PORT}")
    except Exception as e:
        print(f"Serveur: ❌ Erreur de détection: {e}")
    
    print("==============================")

async def main():
    """Fonction principale."""
    
    # Gestion des arguments
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        return
    
    if '--status' in sys.argv:
        check_status()
        return
    
    # Installation/Désinstallation du démarrage
    if INSTALL_MODE:
        if not is_admin():
            request_admin_privileges()
            return
        
        if add_to_startup():
            print("✅ CyberScan Agent installé au démarrage de Windows")
        else:
            print("❌ Erreur lors de l'installation au démarrage")
        return
    
    if UNINSTALL_MODE:
        if not is_admin():
            request_admin_privileges()
            return
        
        if remove_from_startup():
            print("✅ CyberScan Agent supprimé du démarrage de Windows")
        else:
            print("❌ Erreur lors de la suppression du démarrage")
        return
    
    # Afficher les informations de démarrage
    if not SILENT_MODE:
        print("🚀 CyberScan Agent v2.0")
        print(f"Droits: {'Administrateur' if is_admin() else 'Utilisateur standard'}")
        
        in_startup, _ = check_startup_status()
        if not in_startup:
            print("💡 Pour installer au démarrage: CyberScanAgent.exe --install")
        
        print("🔍 Recherche du serveur CyberScan...")
    
    # Lancer la boucle principale
    await agent_loop()
    
    if not SILENT_MODE:
        print("📡 Agent CyberScan terminé")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        if not SILENT_MODE:
            print("\n👋 Agent CyberScan arrêté")
    except Exception as e:
        logging.error(f"Erreur critique: {e}")
        if not SILENT_MODE:
            print(f"❌ Erreur: {e}")
