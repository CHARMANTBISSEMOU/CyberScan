CYBERSCAN AGENT PRO v2.1 - Agent de Surveillance Avancé
==========================================================

🎯 OBJECTIF
-----------
Cet agent professionnel permet aux machines cibles de se connecter automatiquement 
au serveur CyberScan avec des droits administratifs et un lancement automatique au démarrage.

🚀 NOUVEAUTÉS v2.1
------------------

✅ **DROITS ADMINISTRATIFS AUTOMATIQUES**
• Détection automatique des droits admin
• Demande d'élévation si nécessaire
• Accès complet aux informations système

✅ **LANCEMENT AU DÉMARRAGE WINDOWS**
• Installation automatique dans le registre
• Lancement silencieux au démarrage
• Gestion facile de l'installation/désinstallation

✅ **INFORMATIONS SYSTÈME COMPLÈTES**
• Informations hardware (CPU, mémoire, disque)
• Processus en cours d'exécution
• Services système et ports ouverts
• Utilisateurs connectés et sessions

📦 FONCTIONNALITÉS COMPLÈTES
-----------------------------

🔍 DÉCOUVERTE AUTOMATIQUE
• Recherche automatique du serveur CyberScan via mDNS
• Connexion sécurisée WebSocket avec SSL/TLS
• Identification unique de la machine (UUID)
• Reconnexion automatique en cas de déconnexion

📊 COLLECTE AVANCÉE
• Informations système complètes (hardware + software)
• Configuration réseau détaillée
• Surveillance des processus et services
• Utilisation des ressources en temps réel
• Historique des activités système

🔐 SÉCURITÉ RENFORCÉE
• Communication chiffrée avec le serveur
• Authentification par certificats SSL
• Exécution avec droits administratifs
• Mode silencieux pour surveillance discrète

🚀 INSTALLATION
---------------

INSTALLATION STANDARD
--------------------
1. Copiez CyberScanAgentPro.exe sur la machine cible
2. Faites un clic droit → "Exécuter en tant qu'administrateur"
3. Choisissez l'option d'installation :
   
   Installation au démarrage :
   ```
   CyberScanAgentPro.exe --install
   ```
   
   Exécution unique :
   ```
   CyberScanAgentPro.exe
   ```

INSTALLATION SILENCIEUSE
------------------------
Pour un déploiement discret :
```
CyberScanAgentPro.exe --install --silent
```

⚙️ CONFIGURATION REQUISE
------------------------

• Windows 7/8/10/11 (32/64 bits)
• Droits administratifs (pour l'installation)
• Accès réseau (pour se connecter au serveur)
• Python 3.7+ (inclus dans l'exécutable)

🔧 UTILISATION AVANCÉE
---------------------

COMMANDES DISPONIBLES
---------------------
```
CyberScanAgentPro.exe                 Mode normal
CyberScanAgentPro.exe --silent        Mode silencieux
CyberScanAgentPro.exe --install       Installer au démarrage
CyberScanAgentPro.exe --uninstall     Supprimer du démarrage
CyberScanAgentPro.exe --status        Vérifier le statut
CyberScanAgentPro.exe --help          Afficher l'aide
```

VÉRIFICATION DU STATUT
----------------------
```
CyberScanAgentPro.exe --status
```
Affiche :
• ✅ Droits administratifs
• ✅ Statut du démarrage Windows
• ✅ Connexion au serveur
• ✅ Informations système

DÉPLOIEMENT ENTREPRISE
--------------------
Pour un déploiement sur plusieurs machines :
1. Créer un script de déploiement
2. Utiliser GPO ou outil de déploiement
3. Exécuter : `CyberScanAgentPro.exe --install --silent`

📡 PROTOCOLE DE COMMUNICATION
------------------------------

• Port par défaut : 8765 (wss://serveur:8765)
• Protocole : WebSocket avec SSL/TLS
• Format : JSON pour tous les échanges
• Compression : Activée
• Reconnexion automatique

🔍 MESSAGES ÉCHANGÉS
--------------------

1. **HELLO** : Identification complète de l'agent
2. **SYSTEM_INFO** : Informations système détaillées
3. **SCAN_RESULT** : Résultats des scans avancés
4. **HEARTBEAT** : Maintien de connexion
5. **ADMIN_INFO** : Informations privilégiées (si admin)

🚨 DÉPANNAGE
------------

PROBLÈMES COURANTS
-----------------
• **"Nécessite une élévation"** : Normal! L'agent demande les droits admin
• **Serveur non trouvé** : Vérifiez que le serveur CyberScan est en cours d'exécution
• **Connexion refusée** : Vérifiez le firewall et les paramètres réseau
• **Échec installation** : Exécutez vraiment "en tant qu'administrateur"

LOGS ET DÉBOGAGE
-----------------
En mode normal, tous les logs sont affichés dans la console.
En mode silencieux, seules les erreurs critiques sont affichées.

Vérification du registre Windows :
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

🔄 MAINTENANCE
--------------

MISE À JOUR
----------
Pour mettre à jour l'agent :
1. CyberScanAgentPro.exe --uninstall
2. Remplacer l'exécutable
3. CyberScanAgentPro.exe --install

DÉSINSTALLATION COMPLÈTE
------------------------
```
CyberScanAgentPro.exe --uninstall
```
Supprime automatiquement :
• L'entrée du registre Windows
• Les fichiers temporaires
• Les connexions actives

📊 PERFORMANCES
---------------

• Utilisation CPU : < 2% en veille
• Utilisation mémoire : ~80 MB
• Traffic réseau : Minimal
• Impact système : Négligeable
• Démarrage : < 5 secondes

🔒 CONFIDENTIALITÉ ET SÉCURITÉ
-----------------------------

• Aucune donnée personnelle n'est stockée localement
• Toutes les communications sont chiffrées
• L'agent ne collecte que les informations système nécessaires
• Exécution avec droits admin contrôlée et sécurisée
• Pas de transmission de fichiers utilisateur

🏢 AVANTAGES POUR LES ENTREPRISES
---------------------------------

✅ **DÉPLOIEMENT CENTRALISÉ** : Installation silencieuse sur le réseau
✅ **SURVEILLANCE CONTINUE** : Lancement automatique au démarrage
✅ **ACCÈS COMPLET** : Droits admin pour informations détaillées
✅ **MAINTENANCE FACILE** : Gestion simplifiée des installations
✅ **SÉCURITÉ** : Communication chiffrée et authentifiée

📞 SUPPORT TECHNIQUE
-------------------

Pour toute question sur l'agent CyberScan Pro :
• Vérifiez les droits administratifs
• Consultez le statut avec --status
• Assurez-vous que le serveur CyberScan est accessible
• Vérifiez les logs d'erreur

Version : 2.1.0
Date de compilation : 22/05/2026
Développeur : CyberScan Security
Licence : Usage professionnel et entreprise

==========================================================
CYBERSCAN AGENT PRO - Surveillance Avancée avec Droits Admin
