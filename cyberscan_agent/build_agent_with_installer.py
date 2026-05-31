#!/usr/bin/env python3
"""
Script pour construire l'agent CyberScan avec un installeur intégré.
Crée un exécutable unique qui peut s'installer et se lancer automatiquement au démarrage.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def create_self_installer():
    """Crée une version de l'agent qui peut s'auto-installer."""
    
    # Créer un script temporaire qui combine l'agent et l'installateur
    installer_script = '''
import sys
import os
import tempfile
import shutil

# Vérifier si l'agent est déjà installé
def is_installed():
    install_dir = os.path.join(os.environ.get("ProgramFiles", "C:\\\\Program Files"), "CyberScan")
    exe_path = os.path.join(install_dir, "CyberScanAgent.exe")
    return os.path.exists(exe_path)

# Si l'agent n'est pas installé et qu'on a les droits admin, l'installer
if not is_installed() and '--installed' not in sys.argv:
    try:
        # Importer l'installateur
        import installer
        
        installer_instance = installer.CyberScanInstaller()
        
        # Obtenir le chemin de l'exécutable actuel
        current_exe = sys.executable if getattr(sys, 'frozen', False) else __file__
        
        # Installer l'agent
        if installer_instance.install(executable_path=current_exe):
            print("Installation réussie! Lancement de l'agent installé...")
            
            # Lancer l'agent installé avec le flag --installed
            install_dir = installer_instance.install_dir
            installed_exe = os.path.join(install_dir, "CyberScanAgent.exe")
            
            if os.path.exists(installed_exe):
                os.execv(installed_exe, [installed_exe, "--installed"])
        else:
            print("Échec de l'installation. Lancement en mode portable...")
            
    except Exception as e:
        print(f"Erreur lors de l'installation: {e}")
        print("Lancement en mode portable...")

# Importer et lancer l'agent normal
import agent

if __name__ == "__main__":
    if '--installed' in sys.argv or is_installed():
        # Lancer l'agent normalement
        agent.main()
    else:
        # Mode portable ou première exécution
        agent.main()
'''
    
    # Écrire le script combiné
    with open('cyberscan_agent_combined.py', 'w', encoding='utf-8') as f:
        f.write(installer_script)
    
    print("✓ Script combiné créé: cyberscan_agent_combined.py")

def build_executable():
    """Construit l'exécutable avec PyInstaller."""
    
    # Créer le fichier de spécification PyInstaller
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['cyberscan_agent_combined.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('installer.py', '.'),
        ('agent.py', '.'),
    ],
    hiddenimports=[
        'win_scanner',
        'activity_logger',
        'zeroconf',
        'winreg',
        'winshell',
        'win32com.client',
        'ctypes',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CyberScanAgentSetup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # False pour une application Windows sans console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
    version='version_info.txt' if os.path.exists('version_info.txt') else None,
)
'''
    
    with open('CyberScanAgentSetup.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print("✓ Fichier de spécification PyInstaller créé")
    
    # Exécuter PyInstaller
    try:
        print("Construction de l'exécutable avec PyInstaller...")
        subprocess.run([
            sys.executable, '-m', 'PyInstaller',
            '--clean',
            '--onefile',
            'CyberScanAgentSetup.spec'
        ], check=True)
        
        print("✓ Exécutable créé dans le répertoire dist/")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Erreur lors de la construction: {e}")
        return False

def create_installer_exe():
    """Crée un installeur séparé qui peut être distribué."""
    
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['installer.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('agent.py', '.'),
    ],
    hiddenimports=[
        'win_scanner',
        'activity_logger',
        'zeroconf',
        'winreg',
        'winshell',
        'win32com.client',
        'ctypes',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CyberScanAgentInstaller',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # True pour voir la progression de l'installation
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
    version='version_info.txt' if os.path.exists('version_info.txt') else None,
)
'''
    
    with open('CyberScanAgentInstaller.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    try:
        print("Construction de l'installeur...")
        subprocess.run([
            sys.executable, '-m', 'PyInstaller',
            '--clean',
            '--onefile',
            'CyberScanAgentInstaller.spec'
        ], check=True)
        
        print("✓ Installeur créé dans le répertoire dist/")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Erreur lors de la construction de l'installeur: {e}")
        return False

def create_version_info():
    """Crée un fichier d'informations de version pour Windows."""
    
    version_info = '''
# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
# filevers and prodvers should be always a tuple with four items: (1, 2, 3, 4)
# Set not needed items to zero 0.
filevers=(1,0,0,0),
prodvers=(1,0,0,0),
# Contains a bitmask that specifies the valid bits 'flags'r
mask=0x3f,
# Contains a bitmask that specifies the Boolean attributes of the file.
flags=0x0,
# The operating system for which this file was designed.
# 0x4 - NT and there is no need to change it.
OS=0x4,
# The general type of file.
# 0x1 - the file is an application.
fileType=0x1,
# The function of the file.
# 0x0 - the function is not defined for this fileType
subtype=0x0,
# Creation date and time stamp.
date=(0, 0)
),
  kids=[
StringFileInfo(
  [
  StringTable(
    u'040904B0',
    [StringStruct(u'CompanyName', u'CyberScan'),
    StringStruct(u'FileDescription', u'CyberScan Agent - Surveillance de sécurité système'),
    StringStruct(u'FileVersion', u'1.0.0'),
    StringStruct(u'InternalName', u'CyberScanAgent'),
    StringStruct(u'LegalCopyright', u'Copyright © 2024 CyberScan'),
    StringStruct(u'OriginalFilename', u'CyberScanAgent.exe'),
    StringStruct(u'ProductName', u'CyberScan Agent'),
    StringStruct(u'ProductVersion', u'1.0.0')])
  ]), 
VarFileInfo([VarStruct(u'Translation', [1036, 1200])])
  ]
)
'''
    
    with open('version_info.txt', 'w', encoding='utf-8') as f:
        f.write(version_info)
    
    print("✓ Fichier de version créé")

def main():
    """Fonction principale de build."""
    
    print("=== Build CyberScan Agent avec installeur ===")
    
    # Vérifier les dépendances
    try:
        import PyInstaller
        print("✓ PyInstaller trouvé")
    except ImportError:
        print("✗ PyInstaller non installé. Installation...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], check=True)
    
    # Créer le fichier de version
    create_version_info()
    
    # Créer le script combiné
    create_self_installer()
    
    # Demander à l'utilisateur quoi construire
    print("\\nOptions de build:")
    print("1. Agent avec installeur intégré (auto-installation)")
    print("2. Installeur séparé")
    print("3. Les deux")
    
    choice = input("Choisissez une option (1/2/3): ").strip()
    
    if choice in ['1', '3']:
        print("\\n=== Construction de l'agent avec installeur intégré ===")
        if build_executable():
            print("✓ CyberScanAgentSetup.exe créé avec succès!")
        else:
            print("✗ Échec de la construction")
    
    if choice in ['2', '3']:
        print("\\n=== Construction de l'installeur séparé ===")
        if create_installer_exe():
            print("✓ CyberScanAgentInstaller.exe créé avec succès!")
        else:
            print("✗ Échec de la construction de l'installeur")
    
    # Nettoyer les fichiers temporaires
    temp_files = ['cyberscan_agent_combined.py', 'CyberScanAgentSetup.spec', 'CyberScanAgentInstaller.spec']
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    print("\\n=== Build terminé ===")
    print("Les fichiers exécutables sont dans le répertoire 'dist/'")

if __name__ == "__main__":
    main()
