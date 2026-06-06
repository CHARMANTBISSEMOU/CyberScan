# CAHIER DES CHARGES
# CyberScan — Système de Supervision Cybersécurité Multi-Machines
### Version 2.1 | Document de Référence Projet
### Filière : Réseaux & Cybersécurité — KEYCE Academy | Semestre II
### Date : Juin 2026

---

> **Statut du document :** Version finale  
> **Auteur :** Équipe Projet Tutoré 4  
> **Référent pédagogique :** Projet Tuteuré — Semestre II  

---

## TABLE DES MATIÈRES

1. [Contexte et Problématique](#1-contexte-et-problématique)
2. [Introduction et Orientation du Projet](#2-introduction-et-orientation-du-projet)
3. [Architecture Générale](#3-architecture-générale)
4. [Modélisation des Communications](#4-modélisation-des-communications)
5. [Présentation des Fonctionnalités](#5-présentation-des-fonctionnalités)
6. [Scénarios Utilisateurs](#6-scénarios-utilisateurs)
7. [Besoins Fonctionnels](#7-besoins-fonctionnels)
8. [Besoins Non Fonctionnels](#8-besoins-non-fonctionnels)
9. [Outils et Technologies](#9-outils-et-technologies)
10. [Perspectives d'Amélioration](#10-perspectives-damélioration)
11. [Estimation Budgétaire](#11-estimation-budgétaire-production-professionnelle)
12. [Conclusion](#12-conclusion)

---

## 1. CONTEXTE ET PROBLÉMATIQUE

### 1.1 Contexte Général

Créer une startup ou une petite entreprise est déjà un défi immense en soi : trouver des clients, gérer la trésorerie, recruter, se faire connaître. Dans ce quotidien chargé, la cybersécurité passe systématiquement au second plan — non par négligence, mais par manque de ressources. Engager un expert en cybersécurité représente un coût inaccessible pour une structure en cours de création, et les solutions professionnelles du marché (EDR, SIEM, SOC managé) sont conçues et tarifées pour des grandes entreprises.

Ce vide laisse les petites structures dans une situation paradoxale : elles ont des données sensibles (fichiers clients, identifiants, données bancaires, propriété intellectuelle), mais aucun filet de protection opérationnel sur leurs postes de travail. Et pourtant, la grande majorité des cyberattaques ne requiert pas de sophistication technique : elles exploitent de **petites failles de configuration** que n'importe quel scan de base aurait pu détecter — un port mal fermé, un compte administrateur sans mot de passe, un antivirus expiré, une mise à jour Windows en retard depuis des mois.

C'est précisément cette réalité qui est à l'origine de l'échec de nombreuses startups confrontées à un incident de sécurité : non pas parce qu'elles ont été victimes d'une attaque d'État ou d'un groupe cybercriminel organisé, mais parce qu'une faille basique, détectable et corrigeable, n'a jamais été identifiée à temps.

### 1.2 Problématique

> **Comment permettre à une petite entreprise ou une startup disposant de moyens financiers limités de protéger efficacement ses outils de travail informatiques, sans avoir recours à un expert en cybersécurité à temps plein ?**

Cette question structure entièrement notre démarche. Les petites entreprises ont besoin :
- d'un outil **autonome** qui travaille en arrière-plan, sans mobiliser leur temps
- d'un outil **compréhensible** qui traduit les données techniques en recommandations concrètes
- d'un outil **abordable**, voire gratuit à déployer, sans abonnement mensuel prohibitif
- d'un outil **actionnable** qui ne se contente pas de signaler un problème, mais qui indique exactement comment le corriger

Les failles les plus couramment exploitées dans les petites structures sont bien connues :

| Faille fréquente | Conséquence réelle |
|-----------------|-------------------|
| Pare-feu Windows désactivé | Accès direct aux services internes depuis le réseau |
| Antivirus expiré ou désactivé | Ransomware, keylogger, vol de données |
| Ports RDP ou Telnet ouverts | Prise de contrôle à distance de la machine |
| Comptes sans mot de passe | Accès non autorisé aux fichiers et systèmes |
| Mises à jour Windows en retard | Exploitation de vulnérabilités connues publiquement |
| Journaux d'événements non surveillés | Intrusion passée inaperçue pendant des semaines |
| Employé naviguant sur des sites risqués | Téléchargement involontaire de malware |

### 1.3 Notre Réponse : CyberScan

C'est dans ce contexte que s'inscrit **CyberScan**. Notre application est conçue spécifiquement pour répondre à cette problématique : offrir aux petites entreprises et startups un outil de supervision cybersécurité **silencieux, automatique, intelligent et accessible**, leur permettant de détecter et corriger leurs failles de sécurité sans avoir à recruter un expert.

CyberScan cible les structures disposant de **2 à 50 postes Windows** sur un réseau local, avec un responsable informatique (même non spécialisé en cybersécurité) souhaitant :
- Une supervision automatique et silencieuse de toutes les machines
- Des rapports compréhensibles générés par intelligence artificielle
- Des recommandations concrètes avec les commandes exactes à exécuter
- Un déploiement rapide (moins de 30 secondes par machine)

---

## 2. INTRODUCTION ET ORIENTATION DU PROJET

### 2.1 Présentation de la Solution

**CyberScan** est un système de supervision cybersécurité composé de deux applications complémentaires :

```
┌─────────────────────────────────────────────────────┐
│           CYBERSCAN — VUE FONCTIONNELLE             │
├──────────────────────┬──────────────────────────────┤
│   CyberScanAgent.exe │   CyberScan.exe (Admin)      │
│   (Machines cibles)  │   (Poste Administrateur)     │
├──────────────────────┼──────────────────────────────┤
│ - Invisible, silencieux  - Interface graphique PyQt6│
│ - Scan 13 modules        - Dashboard temps réel     │
│ - Collecte activités     - Analyse IA automatique   │
│ - Envoi données WSS      - Génération rapports PDF  │
│ - Auto-détection IP      - Surveillance réseau/trafic│
└──────────────────────┴──────────────────────────────┘
```

### 2.2 Positionnement et Valeur Ajoutée

CyberScan se positionne comme une solution **"clé-en-main"** pour les PME et institutions ne disposant pas de SOC (Security Operations Center) :

- **Démocratisation** : Rend accessible l'audit cybersécurité sans expertise avancée
- **Intelligence artificielle** : Interprétation automatique des données brutes (Groq LLaMA / Claude)
- **Rapport professionnel** : Génération PDF avec score, risques, recommandations
- **Furtivité** : L'agent fonctionne sans fenêtre ni trace visible pour l'utilisateur final
- **Autonomie** : Découverte automatique du serveur (mDNS + scan réseau)

### 2.3 Objectifs du Projet

| Objectif | Indicateur de succès |
|----------|---------------------|
| Déploiement multi-machines | Agent installé et connecté sur 5+ machines |
| Scan complet automatique | 13 modules exécutés en moins de 90 secondes |
| Rapport IA généré | Score + risques + recommandations disponibles |
| Surveillance réseau temps réel | Détection nouveaux appareils en moins de 30 secondes |
| Interface admin intuitive | Navigation sans formation préalable |

---

## 3. ARCHITECTURE GÉNÉRALE

### 3.1 Vue d'Ensemble

```
RÉSEAU LOCAL (LAN)
══════════════════════════════════════════════════════════

  Poste Admin                    Postes Surveillés
  ┌─────────────────┐           ┌──────────┐  ┌──────────┐
  │  CyberScan.exe  │ WSS       │Agent.exe │  │Agent.exe │
  │  ┌───────────┐  │◄─────────►│(silencieux)  (silencieux)
  │  │ Serveur   │  │           └──────────┘  └──────────┘
  │  │ WebSocket │  │
  │  │ :8765/SSL │  │◄ mDNS ──── Découverte automatique
  │  └───────────┘  │
  │  ┌───────────┐  │
  │  │ Interface │  │
  │  │  PyQt6    │  │
  │  └───────────┘  │
  │  ┌───────────┐  │
  │  │  SQLite   │◄─┤── Stockage chiffré (AES)
  │  └───────────┘  │
  └─────────────────┘
           │
           ▼
  ┌─────────────────┐
  │  APIs IA Cloud  │
  │  Groq / Claude  │
  └─────────────────┘
```

### 3.2 Composants Techniques

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Agent** | Python 3 → EXE (PyInstaller) | Collecte données sur poste cible |
| **Serveur WebSocket** | websockets + asyncio + SSL | Réception et orchestration |
| **Interface Admin** | PyQt6 (GUI Windows) | Tableau de bord administrateur |
| **Base de données** | SQLite + chiffrement AES | Stockage historique sécurisé |
| **IA d'analyse** | Groq API (LLaMA 3) / Claude API | Interprétation et scoring |
| **Découverte réseau** | mDNS (Zeroconf) | Auto-détection du serveur |
| **PDF Report** | ReportLab | Génération rapports |

### 3.3 Topologie Réseau Type

```
        [Internet]
             │
             ▼ (APIs IA)
    ┌────────────────┐
    │   Routeur LAN  │  192.168.1.1
    └────────────────┘
           │ LAN
    ┌──────┴──────┬──────────────┐
    ▼             ▼              ▼
[Admin PC]    [PC-RH]       [PC-COMPTA]
192.168.1.10  192.168.1.20  192.168.1.21
CyberScan.exe  Agent.exe     Agent.exe
Port 8765 (WSS)
```

---

## 4. MODÉLISATION DES COMMUNICATIONS

### 4.1 Découverte du Serveur (Connexion Initiale)

L'agent utilise une stratégie en **4 niveaux de priorité** pour trouver le serveur admin :

```
 Démarrage de l'agent
         │
         ▼
 [1. server_config.json ?] ──TROUVÉ──► Connexion WebSocket
         │ NON TROUVÉ
         ▼
 [2. mDNS/Zeroconf (20s)] ──TROUVÉ──► Sauvegarder IP + Connexion
         │ BLOQUÉ
         ▼
 [3. Scan réseau 64 threads] ─TROUVÉ─► Sauvegarder IP + Connexion
    x.x.x.1-254 : port 8765
         │ AUCUN RÉSULTAT
         ▼
 [4. localhost:8765 (fallback)]
```

### 4.2 Flux d'Enregistrement de l'Agent

```
   AGENT (Machine cible)              SERVEUR (Admin)
         │                                 │
         │──── WebSocket Handshake TLS────►│
         │                                 │
         │──── {action: "register",        │
         │      agent_id: "MAC/UUID",      │
         │      os: "Windows 11",          │
         │      hostname: "PC-RH",         │
         │      local_ip: "192.168.1.20",  │
         │      is_admin: true, ...} ─────►│
         │                                 │
         │◄─── {status: "registered"} ─────│
         │                    ┌────────────┤
         │                    │ db.register_machine()
         │                    └────────────┤
         │◄─── {action: "scan", mode: "full"}
```

### 4.3 Flux de Scan Complet (13 Modules en Parallèle)

```
   AGENT — ThreadPoolExecutor (6 workers simultanés)
   ─────────────────────────────────────────────────
   Thread 1: system_info()    → OS, pare-feu, MAJ Windows
   Thread 2: open_ports()     → netstat -ano, classification
   Thread 3: event_logs()     → Security+System logs (500 evt.)
   Thread 4: local_accounts() → Comptes, admin, inactivité
   Thread 5: antivirus()      → Defender, menaces, état
   Thread 6: processes()      → Processus suspects (psutil)

   (Suivants selon disponibilité des workers :)
     network_shares()         → Partages réseau
     suspicious_services()    → Services non-standard
     installed_programs()     → Registre Windows (50 max)
     user_activities()        → Historique navigateur + apps
     port_scan()              → Scan ports style nmap
     integrity_check()        → Vérification fichiers système
     log_analysis()           → Analyse logs style logcheck

   Durée totale : ~60-90s (mode complet) / ~15-25s (mode rapide)
         │
         ▼
   {action: "scan_status", status: "scanning"} → Serveur
   {action: "scan_result", data: {...13 modules}} → Serveur
```

### 4.4 Flux de Collecte des Event Logs Windows

Le module `get_event_logs()` lit les journaux **Security** et **System** de manière **incrémentale** grâce à un filigrane (watermark) :

```
   Journal Windows (Security + System)
            │ win32evtlog.ReadEventLog()
   ┌────────────────────────────────────────────┐
   │ FILTRAGE PAR EVENT ID (500 événements max) │
   │                                            │
   │  4624  Connexion réussie (user, IP, type)  │
   │  4625  Connexion échouée → compteur BruteF │
   │  4720  Création compte utilisateur         │
   │  4732  Ajout compte au groupe Admin        │
   │  4648  Connexion avec credentials explicites│
   │  7045  Nouveau service installé            │
   │  2003  Périphérique USB branché            │
   │  2100  Périphérique USB retiré             │
   └────────────────────────────────────────────┘
            │
   DÉTECTION BRUTE-FORCE :
   Si source_ip a ≥ 3 tentatives (4625) :
     → alerte brute_force_alerts générée
            │
   Sauvegarde watermark (dernier RecordNumber)
   → Prochain scan = lecture incrémentale uniquement
```

### 4.5 Flux de Collecte des Activités Utilisateur

```
   AGENT (activity_logger.py)
            │
            ├── Navigateurs (Chrome, Firefox, Edge, Brave)
            │   └── Lecture bases SQLite History
            │       → URL + titre + date de visite
            │
            ├── Applications lancées
            │   └── Prefetch Windows (%SystemRoot%\Prefetch)
            │       → Nom exécutable + timestamp
            │
            ▼
   Envoyé à l'IA → Classification automatique des risques :
   - Sites torrent/téléchargement illégal  → CRITIQUE
   - Sites de phishing connus              → CRITIQUE
   - Outils de contrôle à distance (AnyDesk, TeamViewer) → ÉLEVÉ
   - Navigation HTTP non chiffrée          → MOYEN
   - VPN/Proxy non autorisé               → MOYEN
   - Messagerie non approuvée             → FAIBLE
```

### 4.6 Flux de Communication avec l'IA (Analyse Chunked)

```
   Serveur reçoit scan_result
            │
   Hash SHA-256 des données
            │ Si hash ≠ dernier hash connu :
            ▼
   ┌──────────────────────────────────────────────────┐
   │          ANALYSE IA CHUNKED                      │
   │                                                  │
   │ CHUNK 1 : Sécurité système & ports               │
   │ → system_info, open_ports, antivirus, port_scan  │
   │ → Appel API (Groq LLaMA ou Claude)               │
   │ → sub_score 0-100 + risques                      │
   │                                                  │
   │ CHUNK 2 : Comptes, journaux & intégrité          │
   │ → local_accounts, event_logs, integrity_check    │
   │ → Appel API → sub_score + risques                │
   │                                                  │
   │ CHUNK 3 : Processus, services & activité         │
   │ → processes, suspicious_services, programs,      │
   │   network_shares, user_activities                │
   │ → Appel API → sub_score + risques                │
   │                                                  │
   │ SYNTHÈSE FINALE                                  │
   │ → Agrégation 3 sous-rapports                     │
   │ → Score pondéré global (0-100)                   │
   │ → Risques consolidés triés par sévérité          │
   │ → Recommandations priorisées + commandes Windows │
   │ → Analyse prédictive (scénario d'attaque)        │
   │ → Diagnostic expert                              │
   └──────────────────────────────────────────────────┘
            │
   Sauvegarde en base SQLite (chiffré AES)
   Envoi PDF automatique au bureau de la machine cible
```

### 4.7 Gestion du Heartbeat

```
   AGENT ──── ping ────► SERVEUR (toutes les 20s)
   SERVEUR ──── pong ───► AGENT

   Chaque message → db.heartbeat(agent_id)
   → UPDATE machines SET last_seen = NOW(), status = 'online'
```

### 4.8 Diagramme de Séquence Complet

```
Agent          Serveur         SQLite          IA API
  │               │               │               │
  │──register────►│──insert──────►│               │
  │◄──registered──│               │               │
  │◄──scan(full)──│               │               │
  │──scan_status──►               │               │
  │  (scanning)                   │               │
  │ [13 modules parallèles]       │               │
  │──scan_result─►│──hash check──►│               │
  │               │◄──last_hash───│               │
  │               │──chunk1──────────────────────►│
  │               │◄──────────────sub_report1──────│
  │               │──chunk2──────────────────────►│
  │               │◄──────────────sub_report2──────│
  │               │──chunk3──────────────────────►│
  │               │◄──────────────sub_report3──────│
  │               │──synthesis───────────────────►│
  │               │◄──────────────final_report─────│
  │               │──save_scan───►│               │
  │◄──deliver_pdf─│               │               │
  │[PDF sur bureau]               │               │
```

---

## 5. PRÉSENTATION DES FONCTIONNALITÉS

### 5.1 Agent CyberScan (CyberScanAgent.exe)

#### F1 — Mode Silencieux Total
L'agent s'exécute **sans aucune interface graphique ni fenêtre console**. Il se cache via les API Windows (`ShowWindow`, `SW_HIDE`). L'utilisateur final ne voit rien.

#### F2 — Auto-Installation au Démarrage Windows
Avec `--install` : crée une entrée dans `HKEY_CURRENT_USER\...\Run`. L'agent redémarre automatiquement à chaque session Windows.

#### F3 — Protection Anti-Double Lancement
Fichier `agent.pid` pour empêcher plusieurs instances. Vérifie via `psutil` ou `tasklist` si le PID existe réellement. Le fichier PID n'est jamais mis en lecture seule (correction v2.1) pour permettre le nettoyage après crash.

#### F4 — Module 1 : Informations Système et Pare-feu
- Nom OS, version, build, architecture, date dernier démarrage
- État pare-feu Windows par profil (Domain, Private, Public) avec actions inbound/outbound
- Mises à jour installées (10 dernières) + **mises à jour en attente** (via PowerShell)

#### F5 — Module 2 : Scan des Ports Ouverts
- Analyse `netstat -ano` (connexions TCP LISTENING)
- Association PID → nom du processus
- Classification par niveau de risque :
  - **CRITIQUE** : Telnet (23), FTP (21), SMB (445), RDP (3389), SQL Server (1433)
  - **MOYEN** : HTTP (80), RPC (135), NetBIOS (139), VNC (5900)
  - **FAIBLE** : ports standards

#### F6 — Module 3 : Analyse des Journaux d'Événements Windows

| Event ID | Événement surveillé |
|----------|---------------------|
| 4624 | Connexion réussie (utilisateur, IP source, type de logon) |
| 4625 | Connexion échouée → **détection brute-force** si ≥ 3 tentatives |
| 4720 | Création d'un nouveau compte utilisateur |
| 4732 | Ajout d'un compte au groupe Administrateurs |
| 4648 | Connexion avec credentials explicites |
| 7045 | Nouveau service Windows installé |
| 2003 | Périphérique USB branché |
| 2100 | Périphérique USB retiré |

#### F7 — Module 4 : Audit des Comptes Locaux
Pour chaque compte : statut admin, désactivé, sans mot de passe, mot de passe expiré, jours d'inactivité, compte Guest actif.

#### F8 — Module 5 : Audit des Partages Réseau
Liste des dossiers partagés avec chemin, permissions, nombre de fichiers exposés, utilisateurs connectés.

#### F9 — Module 6 : Détection des Processus Suspects
Processus depuis `\temp\`, `\tmp\`, `\AppData\Local\Temp\`, `\Downloads\` ou avec des noms imitant des processus système (`svchost32`, `lsass2`, `explorer2`).

#### F10 — Module 7 : Services Windows Suspects
Services démarrés automatiquement depuis des chemins hors `system32`, `Program Files`, `SysWOW64`.

#### F11 — Module 8 : Statut Antivirus / Windows Defender
- Tous les antivirus installés (WMI SecurityCenter2)
- Windows Defender : état, protection temps réel, dernière MAJ signatures, âge des scans
- **Menaces récentes** détectées par Defender (5 dernières)

#### F12 — Module 9 : Programmes Installés
Lecture rapide du registre Windows. Retourne les 50 premiers programmes avec nom, éditeur, version.

#### F13 — Module 10 : Activités Utilisateur
- Sites web visités (Chrome, Firefox, Edge, Brave) — URL, titre, date
- Applications récemment lancées (Prefetch Windows)

#### F14-F16 — Modules 11-13 : Scan Ports (nmap-style), Intégrité Fichiers (Tripwire-style), Analyse Logs (logcheck-style)
Modules avancés disponibles en mode complet pour une couverture exhaustive.

---

### 5.2 Application Administrateur (CyberScan.exe)

#### F17 — Tableau de Bord Principal
Vue d'ensemble temps réel : machines connectées / en scan / hors ligne, scores de sécurité avec codes couleur, progression IA en cours, dernière erreur détectée.

#### F18 — Tableau des Machines Connectées
Colonnes : Hostname, IP, OS, Score, Statut, Dernière vue.  
Actions : lancer scan complet/rapide, voir rapport, envoyer PDF, vérifier emails HIBP.

#### F19 — Rapport Détaillé par Machine
- **Score global 0-100** avec code couleur (CRITIQUE/ÉLEVÉ/MOYEN/BON/EXCELLENT)
- **Résumé exécutif IA** (2-3 phrases)
- **Risques** classés Critical/High/Medium/Low avec description + remédiation + commandes Windows
- **Analyse par module** (13 modules)
- **Recommandations priorisées** urgent/high/medium/low
- **Analyse prédictive** : scénario d'attaque probable, impact estimé post-correction, temps de correction
- **Diagnostic expert** (données brutes pour validation)

#### F20 — Surveillance Réseau
- Tableau : IP, MAC, Hostname, Constructeur, Type, Statut agent, Ports, Score risque
- Statut "Pris en charge" (agent connecté) vs "Non pris en charge"
- **Alerte desktop Windows** à chaque nouvel appareil
- **Interprétation IA** des événements réseau (clic droit)
- Rafraîchissement automatique toutes les 10 secondes

#### F21 — Surveillance Trafic Réseau
Statistiques temps réel : connexions totales, externes, suspectes, alertes.  
Tableau connexions et alertes avec protocole, IP, processus, sévérité.  
Rafraîchissement toutes les 5 secondes.

#### F22 — Génération de Rapports PDF
- **Rapport complet** (administrateur) : données brutes + analyse IA complète
- **Rapport simplifié** (machine cible) : actions de maintenance uniquement
- Livraison automatique sur le bureau de chaque machine via WebSocket

#### F23 — Vérification Emails HIBP
Vérification HaveIBeenPwned avec hash SHA-1 k-anonymity. Résultats enregistrés en base.

#### F24 — Paramètres et Configuration
Gestion des clés API (Groq 1/2/3, Claude), sélection fournisseur par défaut, planification scans.

#### F25 — Scan Programmé Automatique
Boucle vérifiée toutes les 30 secondes. Si heure actuelle = heure programmée → scan automatique de toutes les machines connectées.

#### F26 — Onboarding Wizard
Au premier lancement : configuration guidée des clés API, présentation des fonctionnalités.

#### F27 — Aide Audio Contextuelle
Bouton 🔊 sur chaque onglet → lecture vocale (Windows SAPI TTS) de la description de la page.

---

## 6. SCÉNARIOS UTILISATEURS

### Scénario 1 — Déploiement Initial (10 postes)

```
1. Lancer CyberScan.exe sur le poste admin → serveur WebSocket démarré
2. Wizard → configurer les clés API Groq
3. Copier CyberScanAgent.exe sur clé USB
4. Sur chaque poste : double-clic CyberScanAgent.exe --install (< 30s)
5. Dashboard : 10 machines apparaissent en vert ("online")
6. Scan automatique : ~90s, scores et rapports disponibles
```
**Durée totale estimée : 30 minutes pour 10 postes.**

---

### Scénario 2 — Détection d'une Intrusion (Brute-Force RDP)

```
1. Agent lit Security logs → détecte 5 tentatives (EventID 4625)
   depuis 192.168.1.50 sur le port RDP 3389
2. Alerte brute_force incluse dans le rapport scan
3. L'IA analyse : "Port RDP ouvert + 5 tentatives brute-force
   → risque CRITIQUE"
4. Recommandation + commande :
   netsh advfirewall firewall add rule name="Block Attacker"
   dir=in action=block remoteip=192.168.1.50 protocol=TCP localport=3389
5. Admin applique la correction → machine sécurisée
```

---

### Scénario 3 — Comportement Utilisateur Risqué

```
1. activity_logger collecte historique Chrome
2. Détecte visites sur thepiratebay.org, 1337x.to
3. IA classe : "Navigation sites torrent → risque CRITIQUE
   Risque de téléchargement malware"
4. Recommandation : "Sensibilisation + filtrage DNS (NextDNS)"
5. Admin génère un rapport PDF simplifié envoyé sur le bureau
   de la machine concernée
```

---

### Scénario 4 — Audit de Sécurité Mensuel Automatisé

```
1. Paramètres → Scan programmé → "08:00 chaque lundi"
2. À 8h00 : serveur envoie {action:"scan"} à tous les agents
3. Chaque machine exécute le scan complet (13 modules)
4. Rapports IA générés, PDF livrés sur chaque bureau
5. Admin consulte l'historique → évolution des scores
```

---

### Scénario 5 — Appareil Non Autorisé sur le Réseau

```
1. Surveillance réseau détecte un nouvel appareil
2. Alerte popup Windows sur le poste admin :
   "Nouvel appareil : UNKNOWN-PC (192.168.1.45)"
3. Onglet Réseau : statut "Non pris en charge" (orange)
4. Clic droit sur l'événement → "Interpréter avec l'IA"
5. IA suggère : vérifier appareil, blacklister si non autorisé
```

---

## 7. BESOINS FONCTIONNELS

### BF-01 — Gestion des Agents

| ID | Description | Priorité |
|----|-------------|----------|
| BF-01.1 | Exécution en mode totalement silencieux | CRITIQUE |
| BF-01.2 | Auto-installation au démarrage Windows | HAUTE |
| BF-01.3 | Enregistrement automatique sur le serveur | CRITIQUE |
| BF-01.4 | Résistance aux redémarrages (PID file sécurisé) | HAUTE |
| BF-01.5 | Découverte automatique du serveur (mDNS + scan réseau) | HAUTE |
| BF-01.6 | Mémorisation de l'IP du serveur (server_config.json) | MOYENNE |

### BF-02 — Collecte de Données (13 Modules)

| ID | Description | Priorité |
|----|-------------|----------|
| BF-02.1 | Informations OS et pare-feu (par profil) | CRITIQUE |
| BF-02.2 | Scan ports ouverts avec classification des risques | CRITIQUE |
| BF-02.3 | Lecture Event Logs Windows (incrémental + watermark) | CRITIQUE |
| BF-02.4 | Détection brute-force (≥ 3 tentatives même IP) | CRITIQUE |
| BF-02.5 | Audit comptes locaux (admin, inactifs, sans mdp) | HAUTE |
| BF-02.6 | Détection processus suspects | HAUTE |
| BF-02.7 | Vérification statut antivirus (Defender + tiers) | HAUTE |
| BF-02.8 | Collecte historique navigation web (4 navigateurs) | HAUTE |
| BF-02.9 | Collecte applications récemment lancées | HAUTE |
| BF-02.10 | Vérification intégrité fichiers système | MOYENNE |
| BF-02.11 | Audit partages réseau avec permissions | MOYENNE |

### BF-03 — Communication et Sécurité

| ID | Description | Priorité |
|----|-------------|----------|
| BF-03.1 | Chiffrement TLS de toutes les communications (WSS) | CRITIQUE |
| BF-03.2 | Reconnexion automatique (50 tentatives, délai exponentiel) | HAUTE |
| BF-03.3 | Heartbeat WebSocket (ping/pong toutes les 20s) | HAUTE |
| BF-03.4 | Chiffrement des données en base (AES) | HAUTE |

### BF-04 — Analyse et Rapports

| ID | Description | Priorité |
|----|-------------|----------|
| BF-04.1 | Analyse multi-modèles IA (Groq + Claude) | CRITIQUE |
| BF-04.2 | Score de sécurité 0-100 avec classification | CRITIQUE |
| BF-04.3 | Recommandations priorisées avec commandes Windows | HAUTE |
| BF-04.4 | Génération rapport PDF complet et simplifié | HAUTE |
| BF-04.5 | Livraison automatique PDF sur bureau machine cible | HAUTE |
| BF-04.6 | Éviter ré-analyse si données inchangées (hash SHA-256) | MOYENNE |
| BF-04.7 | Analyse prédictive (scénario d'attaque, temps correction) | MOYENNE |

### BF-05 — Interface Administrateur

| ID | Description | Priorité |
|----|-------------|----------|
| BF-05.1 | Dashboard temps réel avec statuts machines | CRITIQUE |
| BF-05.2 | Surveillance réseau avec détection nouveaux appareils | HAUTE |
| BF-05.3 | Surveillance trafic réseau en temps réel | HAUTE |
| BF-05.4 | Déclenchement manuel de scan (complet/rapide) | HAUTE |
| BF-05.5 | Scan programmé automatique (heure configurable) | HAUTE |
| BF-05.6 | Historique des scans par machine | MOYENNE |
| BF-05.7 | Vérification emails compromis (HIBP) | FAIBLE |
| BF-05.8 | Aide audio contextuelle (TTS Windows) | FAIBLE |

---

## 8. BESOINS NON FONCTIONNELS

### BNF-01 — Performance

| Exigence | Valeur cible |
|----------|-------------|
| Durée scan complet (13 modules) | < 90 secondes |
| Durée scan rapide | < 25 secondes |
| Temps de connexion agent → serveur | < 5 secondes |
| Rafraîchissement interface admin | 5-10 secondes |
| Découverte réseau (64 threads) | < 5 secondes |

### BNF-02 — Sécurité

| Exigence | Implémentation |
|----------|----------------|
| Chiffrement communications | TLS 1.2+ (WSS), certificats auto-signés |
| Chiffrement données locales | AES via crypto_utils.py |
| Chiffrement clés API | Avant stockage SQLite |
| Protection agent PID | Lecture/écriture sans restriction (correction v2.1) |
| Isolation des modules | ThreadPoolExecutor avec timeouts individuels |

### BNF-03 — Fiabilité

| Exigence | Valeur cible |
|----------|-------------|
| Reconnexions agent | 50 tentatives (délai exponentiel, max 5 min) |
| Persistence post-redémarrage | Clé registre Run + server_config.json |
| Tolérance pannes IA | Bascule Groq → Claude → synthèse locale |
| Cohérence base de données | SQLite WAL mode + transactions atomiques |

### BNF-04 — Compatibilité

| Exigence | Détail |
|----------|--------|
| Systèmes cibles | Windows 10 / Windows 11 (64-bit) |
| Serveur admin | Windows 10/11 avec accès réseau LAN |
| Déploiement | EXE standalone (aucune dépendance Python) |
| Navigateurs supportés | Chrome, Firefox, Edge, Brave |

### BNF-05 — Utilisabilité

| Exigence | Détail |
|----------|--------|
| Formation requise (admin) | Aucune (wizard de démarrage) |
| Langue interface | Français |
| Accessibilité | Aide audio TTS sur chaque onglet |
| Temps d'installation agent | < 30 secondes par poste |

### BNF-06 — Maintenabilité

| Exigence | Détail |
|----------|--------|
| Architecture | 13 modules indépendants et extensibles |
| Journalisation | Logs dans %TEMP%\.cyberscan_agent\agent.log |
| Mise à jour | Remplacement de l'EXE uniquement |
| Traçabilité | JOURNAL_MODIFICATIONS.md + backups automatiques |

---

## 9. OUTILS ET TECHNOLOGIES

### 9.1 Langage et Runtime

| Technologie | Version | Usage |
|-------------|---------|-------|
| **Python** | 3.11+ (runtime 3.14) | Langage principal |
| **PyInstaller** | 6.20.0 | Compilation EXE standalone |

### 9.2 Interface Graphique

| Bibliothèque | Usage |
|-------------|-------|
| **PyQt6** | Fenêtres, tableaux, boutons, timers, dialogs |
| **QTimer** | Rafraîchissements automatiques (5s, 10s, 30s) |

### 9.3 Communication Réseau

| Technologie | Usage |
|-------------|-------|
| **websockets** | Communication bidirectionnelle agent ↔ serveur |
| **asyncio** | Gestion asynchrone multi-connexions |
| **ssl / TLS** | Chiffrement WebSocket (WSS) |
| **Zeroconf / mDNS** | Découverte automatique du serveur |
| **socket (TCP)** | Scan réseau direct, détection IP locale |
| **concurrent.futures** | Parallélisation (64 threads pour scan réseau) |

### 9.4 Collecte Système Windows

| Bibliothèque | Usage |
|-------------|-------|
| **wmi** | OS info, pare-feu MSFT_NetFirewallProfile, SecurityCenter2 |
| **win32evtlog** | Lecture journaux Security et System |
| **win32net / win32netcon** | Audit comptes (NetUserEnum) et partages (NetShareEnum) |
| **win32security** | Permissions Windows |
| **win32api / win32gui** | Notifications desktop, gestion fenêtres |
| **psutil** | Processus (pid, exe, cmdline), services, mémoire |
| **winreg** | Registre Windows (programmes installés, démarrage auto) |
| **subprocess** | Commandes netstat, PowerShell, tasklist |
| **ctypes** | API Windows bas niveau (ShowWindow, IsUserAnAdmin) |

### 9.5 Intelligence Artificielle

| Fournisseur | Modèles utilisés | Rôle |
|------------|-----------------|------|
| **Groq** | llama-3.1-8b-instant, llama-3.3-70b-versatile | Analyse principale (rapide, économique) |
| **Anthropic Claude** | claude-3-5-sonnet, claude-3-5-haiku | Analyse de secours (qualité supérieure) |

**Stratégie multi-fournisseur :**  
Tentative dans l'ordre : fournisseur par défaut → Groq 1 → Groq 2 → Groq 3 → Claude.  
En cas d'échec total : synthèse locale (moyenne des sous-scores).

### 9.6 Stockage et Sécurité

| Technologie | Usage |
|-------------|-------|
| **SQLite** | Base de données locale (machines, scans, historique, clés API) |
| **cryptography (AES)** | Chiffrement données sensibles au repos |
| **hashlib (SHA-256)** | Fingerprint des scans (éviter ré-analyse si inchangé) |

### 9.7 Génération de Rapports

| Bibliothèque | Usage |
|-------------|-------|
| **ReportLab** | Génération PDF (rapport complet + rapport simplifié) |
| **Pillow (PIL)** | Manipulation images pour les PDF |
| **base64** | Encodage PDF pour transfert WebSocket |

### 9.8 Environnement de Développement

| Outil | Usage |
|-------|-------|
| **Python venv** | Environnement virtuel isolé |
| **Git** | Gestion des versions du code source |
| **VS Code / PyCharm** | Éditeur de code |

---

## 10. PERSPECTIVES D'AMÉLIORATION

### Court Terme (1-3 mois)

| Amélioration | Impact | Effort |
|-------------|--------|--------|
| **Tableau de bord web** (React + Flask/FastAPI) | Accès navigateur, multi-sites | Élevé |
| **Notifications email** (SMTP) sur anomalies critiques | Alertes proactives | Faible |
| **Agent Linux** (sans win32) | Support serveurs Ubuntu/Debian | Moyen |
| **Correction automatique** (pare-feu, compte Guest) | Action directe sur machines | Moyen |
| **Export CSV/Excel** de l'historique | Analyse externe, BI | Faible |

### Moyen Terme (3-6 mois)

| Amélioration | Impact | Effort |
|-------------|--------|--------|
| **Corrélation multi-machines** | Détection attaques latérales | Élevé |
| **Détection anomalies par ML** (scikit-learn) | Moins de faux positifs | Élevé |
| **Intégration SIEM** (export Syslog/CEF) | Compatibilité Splunk, Elastic | Moyen |
| **2FA pour l'interface admin** | Sécurité accrue | Moyen |
| **API REST** pour intégration tierce | Extensibilité | Moyen |
| **Scan CVE** (NIST NVD API) | Matching versions → CVE connues | Élevé |

### Long Terme (6-12 mois)

| Amélioration | Impact | Effort |
|-------------|--------|--------|
| **Agent Android/iOS** | Surveillance mobile | Très élevé |
| **Mode SaaS** (serveur cloud) | Surveillance multi-sites | Très élevé |
| **LLM local embarqué** (Ollama) | Fonctionnement hors ligne | Très élevé |
| **Playbooks SOAR** (réponse automatisée) | Incidents gérés automatiquement | Élevé |
| **Conformité** RGPD / ISO 27001 checks | Valeur commerciale | Moyen |
| **Marketplace plugins** | Extensibilité communauté | Très élevé |

---

## 11. ESTIMATION BUDGÉTAIRE (PRODUCTION PROFESSIONNELLE)

> Les coûts ci-dessous correspondent à une mise en production commerciale complète.  
> **Devise : FCFA (Franc CFA)** — Base : 1 EUR ≈ 655 FCFA

### 11.1 Coûts de Développement (Phase Initiale)

| Poste | Détail | Durée | Coût (FCFA) |
|-------|--------|-------|-------------|
| Développeur Python Senior | Architecture, modules scan, WebSocket, compilation | 3 mois | 1 500 000 |
| Développeur IA/ML | Intégration Groq/Claude, prompts, chunking | 1 mois | 800 000 |
| Développeur Frontend (PyQt6) | Interface admin, dashboard, rapports | 2 mois | 900 000 |
| Ingénieur Cybersécurité | Audit modules, validation détections | 1 mois | 700 000 |
| Chef de projet | Coordination, documentation, tests | 3 mois | 600 000 |
| Designer UX | Maquettes interface, charte graphique | 0.5 mois | 200 000 |
| Testeur QA | Tests unitaires, intégration, stress test | 1 mois | 400 000 |
| **TOTAL DÉVELOPPEMENT** | | | **5 100 000 FCFA** |

### 11.2 Coûts d'Infrastructure (Annuels)

| Poste | Détail | Coût/Mois | Coût Annuel |
|-------|--------|-----------|-------------|
| APIs IA — Groq | ~10 000 requêtes/mois | 6 500 | 78 000 FCFA |
| APIs IA — Claude | ~2 000 requêtes/mois (secours) | 13 000 | 156 000 FCFA |
| Serveur cloud (SaaS optionnel) | VPS 4 vCPU, 8 GB RAM | 26 000 | 312 000 FCFA |
| Nom de domaine | cyberscan.cm ou .africa | 2 600 | 31 200 FCFA |
| Sauvegarde cloud | Stockage base de données | 3 300 | 39 600 FCFA |
| Certificats SSL | Let's Encrypt | 0 | 0 FCFA |
| **TOTAL INFRASTRUCTURE** | | | **616 800 FCFA/an** |

### 11.3 Coûts de Distribution et Marketing

| Poste | Détail | Coût (FCFA) |
|-------|--------|-------------|
| Signature de code Microsoft | Certificat EV pour signer les EXE (évite alertes antivirus) | 655 000 |
| Site web vitrine | Landing page, documentation, téléchargements | 400 000 |
| Supports commerciaux | Brochures, démos, présentations | 200 000 |
| Campagne marketing digital | LinkedIn, Google Ads (3 mois) | 500 000 |
| Formation revendeurs | Formation commerciale partenaires | 300 000 |
| **TOTAL MARKETING** | | **2 055 000 FCFA** |

### 11.4 Coûts de Maintenance (Annuels)

| Poste | Détail | Coût/An (FCFA) |
|-------|--------|----------------|
| Support technique (50% développeur) | Corrections bugs, mises à jour | 900 000 |
| Mises à jour modèles IA | Adaptation nouveaux modèles Groq/Claude | 200 000 |
| Tests de régression | Après chaque mise à jour Windows | 150 000 |
| Documentation | Manuels, vidéos tutoriels | 200 000 |
| **TOTAL MAINTENANCE** | | **1 450 000 FCFA/an** |

### 11.5 Modèle de Tarification Suggéré

| Offre | Cible | Prix/An (FCFA) | Machines incluses |
|-------|-------|---------------|------------------|
| **Starter** | TPE, associations, écoles | 150 000 | Jusqu'à 5 machines |
| **Business** | PME 10-25 postes | 350 000 | Jusqu'à 25 machines |
| **Enterprise** | Grandes structures, institutions | 750 000 | Machines illimitées |
| **Déploiement** | Installation + formation sur site | 100 000 | Forfait unique |

### 11.6 Résumé Financier Année 1

| Catégorie | Montant (FCFA) |
|-----------|----------------|
| Développement initial | 5 100 000 |
| Infrastructure (an 1) | 616 800 |
| Distribution et Marketing | 2 055 000 |
| Maintenance (an 1) | 1 450 000 |
| **INVESTISSEMENT TOTAL AN 1** | **9 221 800 FCFA** |
| **Équivalent en EUR** | **≈ 14 079 €** |

**Point d'équilibre :**
- Offre Business (350 000 FCFA/an) : **~27 clients PME** pour rentabiliser l'an 1
- À partir de l'an 2 (développement amorti) : **~6 clients** couvrent les frais courants

---

## 12. CONCLUSION

CyberScan répond à un besoin réel et croissant dans les entreprises africaines et camerounaises : disposer d'un outil de supervision cybersécurité efficace, abordable, et adapté aux contraintes locales.

### Points Forts

- **Architecture innovante** : Agent silencieux + IA générative + rapports intelligents
- **13 modules de scan Windows** couvrant l'ensemble de la surface d'attaque
- **Communication sécurisée TLS** avec découverte automatique du serveur (mDNS + scan 64 threads)
- **Interface intuitive** sans formation requise (wizard + aide audio)
- **Rapport PDF automatique** livré sur chaque machine scannée via WebSocket
- **Solution standalone EXE** sans dépendance d'environnement
- **Multi-fournisseur IA** avec bascule automatique Groq → Claude → fallback local

### Limites et Trajectoire

| Limite actuelle | Solution planifiée |
|----------------|-------------------|
| Windows uniquement | Roadmap agent Linux/macOS |
| Dépendance APIs IA cloud | LLM local embarqué (Ollama) |
| Réseau LAN uniquement | Mode SaaS cloud |
| Pas de correction automatique | Playbooks SOAR |

### Impact Pédagogique

Ce projet illustre la maîtrise transversale de :
- **Programmation avancée** : asyncio, threading, WebSocket, PyQt6, PyInstaller
- **Cybersécurité appliquée** : audit Windows, Event Logs, détection brute-force, intégrité
- **Intelligence Artificielle** : intégration LLM, prompt engineering, chunking, multi-modèles
- **Architecture système** : client-serveur, protocoles réseau, chiffrement, découverte mDNS
- **Génie logiciel** : modularité, documentation, compilation, déploiement, rollback
