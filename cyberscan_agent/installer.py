#!/usr/bin/env python3
"""
Script d'installation de l'agent CyberScan avec lancement automatique au démarrage.
Supporte Windows (via le registre) et peut être étendu pour Linux/macOS.
"""

import os
import sys
import shutil
import platform
import subprocess
import winreg
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CyberScanInstaller:
    def __init__(self):
        self.system = platform.system()
        self.app_name = "CyberScanAgent"
        self.install_dir = self._get_install_dir()
        self.executable_name = "CyberScanAgent.exe"
        
    def _get_install_dir(self):
        """Détermine le répertoire d'installation selon le système."""
        if self.system == "Windows":
            # Utiliser Program Files pour Windows
            return os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "CyberScan")
        else:
            # Pour Linux/macOS, utiliser /opt ou ~/Applications
            return "/opt/cyberscan" if os.access("/opt", os.W_OK) else os.path.expanduser("~/cyberscan")
    
    def _get_executable_path(self):
        """Retourne le chemin complet de l'exécutable."""
        return os.path.join(self.install_dir, self.executable_name)
    
    def _is_admin(self):
        """Vérifie si le script est exécuté avec des privilèges d'administrateur."""
        try:
            if self.system == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def install_windows_startup(self):
        """Configure le lancement automatique au démarrage sur Windows."""
        try:
            # Ouvrir la clé de registre pour le démarrage
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )
            
            # Chemin complet de l'exécutable
            exe_path = self._get_executable_path()
            
            # Ajouter l'entrée au registre
            winreg.SetValueEx(
                key,
                self.app_name,
                0,
                winreg.REG_SZ,
                f'"{exe_path}" --silent'
            )
            
            winreg.CloseKey(key)
            logging.info(f"✓ Lancement automatique configuré au démarrage Windows")
            return True
            
        except Exception as e:
            logging.error(f"✗ Erreur configuration démarrage Windows: {e}")
            return False
    
    def install_linux_startup(self):
        """Configure le lancement automatique au démarrage sur Linux (systemd)."""
        try:
            service_content = f"""[Unit]
Description=CyberScan Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart={self._get_executable_path()} --silent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            
            service_path = "/etc/systemd/system/cyberscan-agent.service"
            
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Recharger systemd et activer le service
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', 'cyberscan-agent'], check=True)
            
            logging.info(f"✓ Service systemd configuré pour CyberScan Agent")
            return True
            
        except Exception as e:
            logging.error(f"✗ Erreur configuration service Linux: {e}")
            return False
    
    def install_macos_startup(self):
        """Configure le lancement automatique au démarrage sur macOS (launchd)."""
        try:
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cyberscan.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self._get_executable_path()}</string>
        <string>--silent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
            
            # Créer le répertoire LaunchAgents s'il n'existe pas
            launch_agents_dir = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(launch_agents_dir, exist_ok=True)
            
            plist_path = os.path.join(launch_agents_dir, "com.cyberscan.agent.plist")
            
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            # Charger le service
            subprocess.run(['launchctl', 'load', plist_path], check=True)
            
            logging.info(f"✓ Service launchd configuré pour CyberScan Agent")
            return True
            
        except Exception as e:
            logging.error(f"✗ Erreur configuration service macOS: {e}")
            return False
    
    def install_startup(self):
        """Configure le lancement automatique selon le système."""
        if self.system == "Windows":
            return self.install_windows_startup()
        elif self.system == "Linux":
            return self.install_linux_startup()
        elif self.system == "Darwin":
            return self.install_macos_startup()
        else:
            logging.warning(f"Système non supporté pour le démarrage automatique: {self.system}")
            return False
    
    def copy_executable(self, source_path):
        """Copie l'exécutable dans le répertoire d'installation."""
        try:
            # Créer le répertoire d'installation
            os.makedirs(self.install_dir, exist_ok=True)
            
            # Copier l'exécutable
            dest_path = self._get_executable_path()
            shutil.copy2(source_path, dest_path)
            
            logging.info(f"✓ Exécutable copié vers: {dest_path}")
            return True
            
        except Exception as e:
            logging.error(f"✗ Erreur copie de l'exécutable: {e}")
            return False
    
    def create_shortcut(self):
        """Crée un raccourci sur le bureau (Windows)."""
        if self.system != "Windows":
            return True
            
        try:
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            path = os.path.join(desktop, "CyberScan Agent.lnk")
            target = self._get_executable_path()
            wDir = self.install_dir
            icon = target
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(path)
            shortcut.Targetpath = target
            shortcut.WorkingDirectory = wDir
            shortcut.IconLocation = icon
            shortcut.save()
            
            logging.info(f"✓ Raccourci créé sur le bureau")
            return True
            
        except Exception as e:
            logging.warning(f"Impossible de créer le raccourci: {e}")
            return False
    
    def install(self, executable_path=None, create_shortcut=True, enable_startup=True):
        """Installation complète de l'agent."""
        logging.info("=== Installation de CyberScan Agent ===")
        
        # Vérifier les privilèges
        if not self._is_admin():
            logging.error("✗ Ce script nécessite des privilèges d'administrateur")
            return False
        
        # Déterminer le chemin de l'exécutable
        if not executable_path:
            # Chercher l'exécutable dans le répertoire courant
            current_dir = os.path.dirname(os.path.abspath(__file__))
            executable_path = os.path.join(current_dir, self.executable_name)
            
            if not os.path.exists(executable_path):
                # Chercher dans le sous-répertoire dist
                dist_path = os.path.join(current_dir, "dist", self.executable_name)
                if os.path.exists(dist_path):
                    executable_path = dist_path
                else:
                    logging.error(f"✗ Exécutable non trouvé: {executable_path}")
                    return False
        
        logging.info(f"Source: {executable_path}")
        logging.info(f"Installation vers: {self.install_dir}")
        
        # Copier l'exécutable
        if not self.copy_executable(executable_path):
            return False
        
        # Configurer le démarrage automatique
        if enable_startup:
            if not self.install_startup():
                logging.warning("Le démarrage automatique n'a pas pu être configuré")
        
        # Créer un raccourci
        if create_shortcut:
            self.create_shortcut()
        
        logging.info("✓ Installation terminée avec succès!")
        return True
    
    def uninstall(self):
        """Désinstalle l'agent."""
        logging.info("=== Désinstallation de CyberScan Agent ===")
        
        if not self._is_admin():
            logging.error("✗ Ce script nécessite des privilèges d'administrateur")
            return False
        
        try:
            # Supprimer le démarrage automatique
            if self.system == "Windows":
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        0,
                        winreg.KEY_SET_VALUE
                    )
                    winreg.DeleteValue(key, self.app_name)
                    winreg.CloseKey(key)
                    logging.info("✓ Entrée de démarrage automatique supprimée")
                except FileNotFoundError:
                    pass
            elif self.system == "Linux":
                try:
                    subprocess.run(['systemctl', 'disable', 'cyberscan-agent'], check=True)
                    subprocess.run(['systemctl', 'stop', 'cyberscan-agent'], check=True)
                    os.remove('/etc/systemd/system/cyberscan-agent.service')
                    subprocess.run(['systemctl', 'daemon-reload'], check=True)
                    logging.info("✓ Service systemd supprimé")
                except:
                    pass
            elif self.system == "Darwin":
                try:
                    plist_path = os.path.expanduser("~/Library/LaunchAgents/com.cyberscan.agent.plist")
                    subprocess.run(['launchctl', 'unload', plist_path], check=True)
                    os.remove(plist_path)
                    logging.info("✓ Service launchd supprimé")
                except:
                    pass
            
            # Supprimer le raccourci
            if self.system == "Windows":
                try:
                    desktop = winshell.desktop()
                    shortcut_path = os.path.join(desktop, "CyberScan Agent.lnk")
                    if os.path.exists(shortcut_path):
                        os.remove(shortcut_path)
                        logging.info("✓ Raccourci supprimé")
                except:
                    pass
            
            # Supprimer le répertoire d'installation
            if os.path.exists(self.install_dir):
                shutil.rmtree(self.install_dir)
                logging.info("✓ Fichiers d'installation supprimés")
            
            logging.info("✓ Désinstallation terminée!")
            return True
            
        except Exception as e:
            logging.error(f"✗ Erreur lors de la désinstallation: {e}")
            return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Installateur de CyberScan Agent")
    parser.add_argument("--install", action="store_true", help="Installer l'agent")
    parser.add_argument("--uninstall", action="store_true", help="Désinstaller l'agent")
    parser.add_argument("--executable", help="Chemin vers l'exécutable à installer")
    parser.add_argument("--no-startup", action="store_true", help="Ne pas configurer le démarrage automatique")
    parser.add_argument("--no-shortcut", action="store_true", help="Ne pas créer de raccourci")
    
    args = parser.parse_args()
    
    installer = CyberScanInstaller()
    
    if args.install:
        success = installer.install(
            executable_path=args.executable,
            create_shortcut=not args.no_shortcut,
            enable_startup=not args.no_startup
        )
        sys.exit(0 if success else 1)
    elif args.uninstall:
        success = installer.uninstall()
        sys.exit(0 if success else 1)
    else:
        # Mode interactif
        print("=== CyberScan Agent Installer ===")
        print("1. Installer l'agent")
        print("2. Désinstaller l'agent")
        
        choice = input("Choisissez une option (1/2): ").strip()
        
        if choice == "1":
            success = installer.install()
            sys.exit(0 if success else 1)
        elif choice == "2":
            success = installer.uninstall()
            sys.exit(0 if success else 1)
        else:
            print("Option invalide")
            sys.exit(1)

if __name__ == "__main__":
    main()
