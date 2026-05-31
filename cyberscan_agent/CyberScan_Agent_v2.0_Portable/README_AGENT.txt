CYBERSCAN AGENT v2.0 - Agent de Surveillance Réseau
====================================================

🎯 OBJECTIF
-----------
Cet agent permet aux machines cibles de se connecter automatiquement 
au serveur CyberScan et de fournir des informations système détaillées.

📦 FONCTIONNALITÉS
-----------------

🔍 DÉCOUVERTE AUTOMATIQUE
• Recherche automatique du serveur CyberScan via mDNS (Zeroconf)
• Connexion sécurisée WebSocket avec SSL/TLS
• Identification unique de la machine (UUID)

📊 COLLECTE D'INFORMATIONS
• Informations système (OS, hostname, architecture)
• Configuration réseau (IP, MAC, interfaces)
• Processus en cours d'exécution
• Services système et état des ports
• Utilisation CPU, mémoire, disque
• Informations sur les utilisateurs connectés

🔐 SÉCURITÉ
-----------
• Communication chiffrée avec le serveur
• Authentification par certificats SSL
• Pas de stockage persistant des données sensibles
• Mode silencieux disponible pour déploiement discret

🚀 INSTALLATION
---------------

1. Copiez CyberScanAgent.exe sur la machine cible
2. Exécutez l'agent avec les options souhaitées :
   
   Mode normal (avec console visible) :
   ```
   CyberScanAgent.exe
   ```
   
   Mode silencieux (en arrière-plan) :
   ```
   CyberScanAgent.exe --silent
   ```

3. L'agent va automatiquement :
   • Rechercher le serveur CyberScan sur le réseau
   • Se connecter et s'identifier
   • Envoyer les informations système
   • Attendre les commandes de scan

⚙️ CONFIGURATION REQUISE
------------------------

• Windows 7/8/10/11 (32/64 bits)
• Accès réseau (pour se connecter au serveur)
• Droits utilisateur standard (admin non requis)
• Python 3.7+ (inclus dans l'exécutable)

🔧 UTILISATION AVANCÉE
---------------------

MODES DE DÉMARRAGE
------------------
Normal : CyberScanAgent.exe
Silencieux : CyberScanAgent.exe --silent
Aide : CyberScanAgent.exe --help

CONNEXION MANUELLE
-----------------
Si la découverte automatique échoue, l'agent affichera 
l'adresse IP du serveur trouvé pour connexion manuelle.

LOGS ET DÉBOGAGE
-----------------
En mode normal, tous les logs sont affichés dans la console.
En mode silencieux, seules les erreurs critiques sont affichées.

📡 PROTOCOLE DE COMMUNICATION
------------------------------

L'agent communique avec le serveur via WebSocket sécurisé :
• Port par défaut : 8765 (wss://serveur:8765)
• Protocole : WebSocket avec SSL/TLS
• Format : JSON pour tous les échanges
• Compression : Activée pour optimiser la bande passante

🔍 MESSAGES ÉCHANGÉS
--------------------

1. **HELLO** : Identification de l'agent
2. **SYSTEM_INFO** : Informations système complètes
3. **SCAN_RESULT** : Résultats des scans demandés
4. **HEARTBEAT** : Maintien de connexion (toutes les 30 secondes)

🚨 DÉPANNAGE
------------

PROBLÈMES CONNUS
---------------
• **Serveur non trouvé** : Vérifiez que le serveur CyberScan est en cours d'exécution
• **Connexion refusée** : Vérifiez le firewall et les paramètres réseau
• **Certificat SSL** : Acceptez le certificat si avertissement de sécurité

LOGS D'ERREURS
--------------
Les erreurs sont affichées directement dans la console ou 
enregistrées dans les logs système Windows.

🔄 MISES À JOUR
--------------

Pour mettre à jour l'agent :
1. Arrêtez l'agent en cours d'exécution
2. Remplacez CyberScanAgent.exe par la nouvelle version
3. Redémarrez l'agent

📊 PERFORMANCES
---------------

• Utilisation CPU : < 1% en veille
• Utilisation mémoire : ~50 MB
• Traffic réseau : Minimal (compression activée)
• Impact système : Négligeable

🔒 CONFIDENTIALITÉ
-----------------

• Aucune donnée personnelle n'est stockée localement
• Toutes les communications sont chiffrées
• L'agent ne collecte que les informations système nécessaires
• Pas de transmission de fichiers ou de données utilisateur

📞 SUPPORT
----------

Pour toute question sur l'agent CyberScan :
• Vérifiez la connexion réseau avec le serveur
• Consultez les logs d'erreur dans la console
• Assurez-vous que le serveur CyberScan est accessible

Version : 2.0.0
Date de compilation : 22/05/2026
Développeur : CyberScan Security
Licence : Usage interne et surveillance réseau

====================================================
CYBERSCAN AGENT - Votre Yeil sur le Réseau
