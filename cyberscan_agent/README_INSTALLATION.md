# CyberScan Agent - Installation et Configuration

## Vue d'ensemble

CyberScan Agent est un agent de surveillance de sécurité qui se connecte automatiquement au serveur CyberScan Admin et effectue des scans de sécurité réguliers sur les machines du réseau.

## Fonctionnalités d'installation

- ✅ Installation automatique avec droits administrateur
- ✅ Lancement automatique au démarrage du système
- ✅ Support Windows (via registre), Linux (systemd), macOS (launchd)
- ✅ Mode silencieux pour le démarrage automatique
- ✅ Création de raccourcis sur le bureau
- ✅ Désinstallation complète

## Méthodes d'installation

### 1. Installation automatique (recommandée)

#### Option A: Exécutable avec installeur intégré
```bash
# Lancer simplement l'exécutable - il s'installera automatiquement
CyberScanAgentSetup.exe
```

#### Option B: Installeur séparé
```bash
# Lancer l'installeur
CyberScanAgentInstaller.exe --install
```

### 2. Installation manuelle via script

```bash
# Installation avec lancement au démarrage
python installer.py --install --executable CyberScanAgent.exe

# Installation sans lancement au démarrage
python installer.py --install --executable CyberScanAgent.exe --no-startup

# Désinstallation
python installer.py --uninstall
```

## Configuration requise

### Windows
- Windows 7 ou supérieur
- Droits administrateur pour l'installation
- .NET Framework 4.5+ (généralement inclus)

### Linux
- systemd (pour le lancement automatique)
- Droits root/sudo pour l'installation

### macOS
- macOS 10.10+ (Yosemite)
- Droits administrateur pour l'installation

## Emplacements d'installation

### Windows
```
C:\Program Files\CyberScan\CyberScanAgent.exe
```

### Linux
```
/opt/cyberscan/CyberScanAgent
```

### macOS
```
~/cyberscan/CyberScanAgent
```

## Configuration du démarrage automatique

### Windows
L'agent est ajouté au registre:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### Linux
Un service systemd est créé:
```
/etc/systemd/system/cyberscan-agent.service
```

### macOS
Un service launchd est créé:
```
~/Library/LaunchAgents/com.cyberscan.agent.plist
```

## Construction des exécutables

### Prérequis
```bash
pip install -r requirements_installer.txt
```

### Build
```bash
python build_agent_with_installer.py
```

Options disponibles:
1. Agent avec installeur intégré (auto-installation)
2. Installeur séparé
3. Les deux

## Utilisation

### Mode normal
L'agent se connecte automatiquement au serveur CyberScan Admin via:
- Découverte mDNS sur le réseau local
- Fallback sur localhost:8765 si aucun serveur trouvé

### Mode silencieux
```bash
CyberScanAgent.exe --silent
```
Le mode silencieux réduit les logs et est utilisé pour le démarrage automatique.

## Dépannage

### L'agent ne se lance pas au démarrage
1. Vérifier que l'installation a été faite avec des droits administrateur
2. Vérifier l'entrée dans le registre Windows (Windows) ou le service (Linux)

### L'agent ne trouve pas le serveur
1. Vérifier que le serveur CyberScan Admin est en cours d'exécution
2. Vérifier la connectivité réseau
3. Vérifier que le pare-feu ne bloque pas les connexions

### Désinstallation
```bash
# Via l'installeur
python installer.py --uninstall

# Manuellement (Windows)
# Supprimer l'entrée du registre
# Supprimer le dossier C:\Program Files\CyberScan
```

## Logs

### Windows
Les logs sont écrits dans:
- Event Viewer (si configuré)
- Console (mode non silencieux)

### Linux/macOS
Les logs sont écrits dans:
- syslog/journal (service systemd)
- Console (mode non silencieux)

## Sécurité

- L'agent utilise une connexion WebSocket sécurisée (WSS)
- Les communications sont chiffrées avec SSL/TLS
- L'agent ne nécessite pas de configuration manuelle des identifiants

## Support

Pour toute question ou problème, contacter l'administrateur système ou consulter la documentation complète de CyberScan.

---

**Note importante**: L'agent nécessite des droits administrateur pour s'installer et se configurer pour le lancement automatique au démarrage.
