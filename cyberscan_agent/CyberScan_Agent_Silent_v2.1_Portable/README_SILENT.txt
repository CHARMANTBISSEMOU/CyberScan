CYBERSCAN AGENT SILENT v2.1 - Agent d'Arrière-Plan
======================================================

🔇 **AGENT COMPLÈTEMENT SILENCIEUX - PAS D'INTERFACE**

Cet agent fonctionne entièrement en arrière-plan sans aucune interface 
visible ni console. Il collecte les informations système et les envoie 
au serveur CyberScan de manière transparente.

🎯 **OBJECTIF**
-----------
Surveiller les machines cibles de manière discrète sans que 
l'utilisateur ne s'aperçoive de l'installation ou de l'exécution.

🔧 **CARACTÉRISTIQUES PRINCIPALES**
------------------------------

✅ **MODE SILENCIEUX TOTAL**
• Pas de console visible
• Pas d'interface graphique
• Processus invisible dans la barre des tâches
• Exécution complète en arrière-plan

✅ **STOCKAGE SÉCURISÉ**
• Données stockées dans des fichiers temporaires
• Fichiers en lecture seule après création
• Emplacement : `%TEMP%\.cyberscan_agent\`
• Nettoyage automatique des fichiers

✅ **INSTALLATION AUTOMATIQUE**
• Installation au démarrage de Windows
• Redémarrage automatique avec droits admin
• Lancement silencieux au boot
• Désinstallation propre

✅ **COMMUNICATION DISCRÈTE**
• Connexion WebSocket chiffrée
• Découverte automatique du serveur
• Reconnexion automatique en cas de déconnexion
• Pas de logs visibles

📦 **CONTENU DU PACKAGE**
------------------------

• CyberScanAgentSilent.exe (17.3 Mo) - Agent silencieux
• README_SILENT.txt - Ce fichier de documentation

🚀 **INSTALLATION SILENCIEUSE**
---------------------------

INSTALLATION STANDARD
--------------------
1. Copiez CyberScanAgentSilent.exe sur la machine cible
2. Exécutez en tant qu'administrateur :
   ```
   CyberScanAgentSilent.exe --install
   ```
3. L'agent s'installera automatiquement au démarrage de Windows

INSTALLATION MANUELLE
--------------------
Pour un lancement unique sans installation :
```
CyberScanAgentSilent.exe
```

L'agent démarrera en arrière-plan et se connectera au serveur.

🔧 **COMMANDES DISPONIBLES**
-------------------------

```
CyberScanAgentSilent.exe --install    # Installation au démarrage
CyberScanAgentSilent.exe --uninstall  # Suppression du démarrage
CyberScanAgentSilent.exe --help       # Affiche l'aide
CyberScanAgentSilent.exe              # Lancement silencieux
```

📊 **FONCTIONNEMENT TECHNIQUE**
------------------------------

1. **DÉMARRAGE**
   • L'agent cache immédiatement la console
   • Vérifie si une autre instance est en cours
   • Crée le dossier de données temporaires
   • Sauvegarde le PID du processus

2. **CONNEXION**
   • Découverte automatique du serveur via mDNS
   • Connexion WebSocket sécurisée (WSS)
   • Envoi des informations système complètes

3. **SURVEILLANCE**
   • Attend les commandes du serveur
   • Exécute les scans système en arrière-plan
   • Stocke les résultats dans des fichiers temporaires
   • Envoie les résultats au serveur

4. **PERSISTENCE**
   • Redémarrage automatique en cas de crash
   • Reconnexion automatique au serveur
   • Mise à jour silencieuse possible

📁 **EMPLACEMENT DES DONNÉES**
----------------------------

```
%TEMP%\.cyberscan_agent\
├── system_info.json     # Informations système
├── scan_results.json    # Résultats des scans
├── agent.log           # Logs d'erreur uniquement
└── agent.pid           # PID du processus
```

**Tous les fichiers sont en lecture seule après création**

🔍 **INFORMATIONS COLLECTÉES**
---------------------------

**Informations système de base :**
• Système d'exploitation
• Nom d'hôte et adresse IP
• Architecture et processeur
• Version Python et plateforme

**Informations avancées (droits admin) :**
• Nombre de cœurs CPU
• Mémoire totale
• Utilisation des disques
• Temps de démarrage
• Nombre de processus

**Résultats des scans :**
• Informations système complètes
• Processus en cours d'exécution
• Connexions réseau actives
• Utilisateurs connectés
• Services système

🛡️ **SÉCURITÉ ET DISCRÉTION**
----------------------------

✅ **INVISIBILITÉ**
• Pas d'icône ni de raccourci visible
• Processus masqué dans la barre des tâches
• Pas de notification système
• Fichiers temporaires cachés

✅ **PROTECTION DES DONNÉES**
• Fichiers en lecture seule
• Stockage dans le dossier temporaire
• Communication chiffrée SSL/TLS
• Pas de logs en clair

✅ **ANTI-DÉTECTION**
• Nom de processus générique
• Consommation CPU minimale (< 2%)
• Traffic réseau réduit
• Pas d'activité disque excessive

🔧 **DÉPANNAGE**
---------------

**L'agent ne se lance pas :**
1. Vérifiez que vous avez les droits administratifs
2. Assurez-vous que Windows Defender ne le bloque pas
3. Vérifiez que le serveur CyberScan est accessible

**Pas de connexion au serveur :**
1. Vérifiez la connexion réseau
2. Assurez-vous que le port 8765 n'est pas bloqué
3. Vérifiez que le serveur CyberScan est en cours d'exécution

**Pour vérifier l'installation :**
1. Ouvrez le Registre Windows
2. Allez dans : `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
3. Cherchez "CyberScanAgent"

🔄 **DÉSINSTALLATION**
-----------------

DÉSINSTALLATION AUTOMATIQUE
--------------------------
```
CyberScanAgentSilent.exe --uninstall
```

DÉSINSTALLATION MANUELLE
------------------------
1. Supprimez la valeur "CyberScanAgent" du registre
2. Arrêtez le processus CyberScanAgentSilent.exe
3. Supprimez le dossier `%TEMP%\.cyberscan_agent\`

📊 **PERFORMANCES**
---------------

• Utilisation CPU : < 2% en veille
• Utilisation mémoire : ~70 MB
• Traffic réseau : Minimal
• Impact système : Négligeable
• Démarrage : < 3 secondes

🏢 **AVANTAGES POUR LES ENTREPRISES**
-----------------------------------

✅ **DÉPLOIEMENT DISCRET** : Installation invisible pour les utilisateurs
✅ **SURVEILLANCE CONTINUE** : Fonctionne 24/7 en arrière-plan
✅ **MAINTENANCE FACILE** : Gestion centralisée via le serveur
✅ **SÉCURITÉ** : Communication chiffrée et données protégées
✅ **CONFORMITÉ** : Logs minimaux et respect de la vie privée

📞 **SUPPORT TECHNIQUE**
-------------------

Pour toute question sur l'agent silencieux :
• L'agent est conçu pour fonctionner de manière autonome
• Les erreurs sont loguées uniquement dans le fichier agent.log
• Le serveur CyberScan gère la communication et les commandes

---
**CyberScan Silent Agent v2.1 - Surveillance invisible**

Version : 2.1.0
Date de compilation : 22/05/2026
Développeur : CyberScan Security
Type : Agent silencieux d'arrière-plan

**Cet agent est conçu pour une surveillance discrète et professionnelle.**
