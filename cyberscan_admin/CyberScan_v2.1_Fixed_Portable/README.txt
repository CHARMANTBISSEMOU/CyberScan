CYBERSCAN v2.0 - Application de Sécurité Réseau
==================================================

🚀 FONCTIONNALITÉS PRINCIPALES
---------------------------

🖥️ ONGLET MACHINES
• Gestion des agents de scan
• Tableau de bord principal
• Scores de sécurité
• Actions de scan automatisées

🌐 ONGLET RÉSEAU (NOUVEAU)
• Scan automatique toutes les 20 secondes
• Découverte d'appareils sur le réseau local
• Identification par MAC, hostname et type d'appareil
• Alertes desktop pour nouveaux appareils détectés
• Base de données locale avec historique (1 mois)

📊 ONGLET TRAFIC (NOUVEAU)
• Surveillance des connexions réseau en temps réel
• Détection d'anomalies et menaces
• Analyse des processus et ports suspects
• Alertes intelligentes avec classification de risque
• Statistiques détaillées du trafic

📦 INSTALLATION
---------------

1. Décompressez le dossier CyberScan dans un emplacement de votre choix
2. Double-cliquez sur CyberScan.exe pour lancer l'application
3. L'application va créer automatiquement les fichiers nécessaires :
   - cyberscan.db (base de données)
   - cyberscan.log (fichier de logs)

⚙️ CONFIGURATION REQUISE
------------------------

• Windows 10/11 (64 bits)
• 4 Go RAM minimum
• 500 Mo d'espace disque disponible
• Connexion réseau active
• Droits utilisateur standard (admin non requis)

🔥 UTILISATION
--------------

Au premier lancement :
1. L'interface s'ouvre avec 3 onglets
2. Le scan réseau démarre automatiquement
3. La surveillance trafic peut être démarrée manuellement
4. Les alertes desktop s'affichent pour les activités suspectes

Pour la surveillance trafic :
1. Allez dans l'onglet "📊 Trafic"
2. Cliquez sur "▶️ Démarrer"
3. Les statistiques s'affichent en temps réel
4. Les alertes apparaissent dans le tableau inférieur

📊 FICHIERS GÉNÉRÉS
-------------------

• cyberscan.db : Base de données SQLite avec historique
• cyberscan.log : Logs d'application pour dépannage
• cyberscan.db-journal : Fichier temporaire SQLite

🔒 SÉCURITÉ
-----------

• Toutes les données sont stockées localement
• Aucune communication avec des serveurs externes
• Scan réseau non-intrusif (ping et ports standards)
• Surveillance trafic en lecture seule

🚨 ALERTES
----------

Les alertes desktop s'affichent pour :
• Nouveaux appareils détectés sur le réseau
• Connexions réseau suspectes
• Processus inhabituels
• Ports à risque utilisés

📞 SUPPORT
----------

Pour toute question ou problème :
• Vérifiez le fichier cyberscan.log pour les erreurs
• Assurez-vous que Windows Defender ne bloque pas l'application
• Redémarrez l'application si nécessaire

📝 NOTES
--------

• L'application utilise psutil pour la surveillance système
• Les données sont conservées pendant 1 mois maximum
• Le scan réseau s'adapte automatiquement à votre configuration
• La surveillance trafic nécessite des ressources système modérées

Version : 2.0.0
Date de compilation : 22/05/2026
Développeur : CyberScan Security
Licence : Usage privé et éducatif

==================================================
CYBERSCAN - Votre Sécurité Réseau Locale
