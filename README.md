# 🔒 CYBERSCAN v2.1

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/PyQt6-0078D4?style=for-the-badge&logo=qt&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-AES--256--green?style=for-the-badge&logo=shield&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Groq%20%7C%20Claude-purple?style=for-the-badge&logo=artificial-intelligence&logoColor=white" />
  <img src="https://img.shields.io/badge/Alerts-WhatsApp%20API-25D366?style=for-the-badge&logo=whatsapp&logoColor=white" />
</p>

<p align="center">
  <b>Système d'Audit et de Surveillance de Sécurité Informatique piloté par Intelligence Artificielle</b>
</p>

---

## 📋 Table des Matières

- [Introduction](#introduction)
- [Fonctionnalités Clés](#fonctionnalités-clés)
- [Cas d'Usage : Le Gardien Silencieux](#cas-dusage--le-gardien-silencieux)
- [Architecture & Technologies](#architecture--technologies)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Sécurité et Conformité](#sécurité-et-conformité)
- [Développement et Compilation](#développement-et-compilation)
- [Auteur et Remerciements](#auteur-et-remerciements)

---

## 🎯 Introduction

**CyberScan** est une solution complète d'audit et de surveillance de sécurité informatique spécialement conçue pour démocratiser la sécurité au sein des TPE, PME et startups. En combinant une architecture distribuée (Agent/Serveur), l'intelligence artificielle (LLM) et un chiffrement de niveau militaire, le système permet de déceler les vulnérabilités de manière proactive, sans nécessiter d'expertise technique (SOC).

---

## ✨ Fonctionnalités Clés

### 🖥️ Console d'Administration (CyberScan Admin)
- **Dashboard Synthétique** : Vue d'ensemble du parc avec scores de sécurité.
- **Paramétrage des Alertes** : Configuration du numéro de téléphone pour recevoir les alertes WhatsApp.
- **Analyse IA Optimisée** : Évaluation des vulnérabilités via Groq/Claude, avec *Chunking* (découpage sémantique) et *Cache SHA-256* pour économiser les requêtes inutiles.
- **Rapports PDF** : Génération de rapports professionnels consolidés.

### 🛡️ Agent Autonome (CyberScan Agent)
- **Mode Daemon (Arrière-plan)** : L'agent tourne silencieusement et s'exécute automatiquement au démarrage de Windows.
- **Monitoring Proactif** : Collecte WMI (processus, pare-feu), analyse des ports et détection des anomalies dans les Event Logs et les historiques de navigation (SQLite anti-verrouillage).
- **Communication Sécurisée** : WebSocket SSL/TLS avec reconnexion automatique.

### 📱 Alerting Temps Réel (WhatsApp)
- Transmission instantanée (via Green API) des alertes critiques (ex: visite de sites frauduleux, détection de malware) directement sur le smartphone de l'administrateur, contournant le besoin de surveiller un tableau de bord en permanence.

---

## 🕵️‍♂️ Cas d'Usage : Le Gardien Silencieux

Ce scénario démontre la réactivité de CyberScan en conditions réelles :
1. **Fermeture du poste de contrôle** : L'application administrateur est fermée. L'Agent Windows continue d'opérer en mode *daemon*.
2. **Simulation d'un comportement à risque** : Un utilisateur navigue sur une plateforme dangereuse (ex: ThePirateBay).
3. **Détection** : L'agent détecte l'anomalie en interrogeant les bases SQLite du navigateur en mode asynchrone (sans bloquer l'utilisateur).
4. **Transmission de l'alerte** : Lors de son cycle de vérification (toutes les 3 minutes), l'agent qualifie le risque de "Critique" et pousse l'alerte sur le smartphone de l'administrateur via **WhatsApp**.

---

## 🏗️ Architecture & Technologies

```
┌─────────────────────────────────────────────────────────────┐
│                    CYBERSCAN ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │  CONSOLE ADMIN   │◄───────►│  AGENT WINDOWS   │          │
│  │   (PyQt6 GUI)    │ WebSocket│  (Service)       │          │
│  │                  │  SSL/TLS │                  │          │
│  │ • Dashboard      │         │ • WMI Collect    │          │
│  │ • Paramètres     │         │ • Port Scan      │          │
│  │ • WhatsApp Alerts│         │ • Browser Logs   │          │
│  │ • AI Analysis    │         │ • Event Log      │          │
│  └────────┬─────────┘         └──────────────────┘          │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │   SQLITE DB      │         │   AI & APIs      │          │
│  │  (AppLocalData)  │         │  • Groq API      │          │
│  │                  │         │  • Claude API    │          │
│  │ • machines       │         │  • Green API     │          │
│  │ • scans/cache    │         │    (WhatsApp)    │          │
│  └──────────────────┘         └──────────────────┘          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Pile Technologique :**
- **Interface** : Python 3.12 + PyQt6
- **Communication** : WebSockets + SSL/TLS 1.3
- **Base de données** : SQLite 3 (sauvegardée dans AppData pour éviter les erreurs de permissions)
- **Chiffrement** : AES-256-GCM + PBKDF2
- **Système Windows** : WMI + psutil + win32api
- **Packaging** : PyInstaller + Inno Setup 6

---

## 🚀 Installation

### 📦 Installation Automatique (Setup Recommandé)
Un exécutable d'installation (Setup) "clé en main" est disponible pour déployer en un clic la **Console Admin** et l'**Agent Silencieux v2.1**.

**Processus :**
1. Allez dans le dossier **[Setup/](Setup/)** de ce dépôt GitHub.
2. Cliquez sur le fichier **`CyberScan_Setup_Final.exe`** et téléchargez-le (Download raw file).
3. Exécutez le Setup sur votre machine Windows.
4. L'installeur copiera les fichiers, installera les certificats SSL, déploiera l'Agent caché en arrière-plan et placera les raccourcis sur votre bureau.

> **💡 Note :** L'agent d'analyse de vulnérabilités et de surveillance d'URL se lancera tout seul au démarrage de la machine et fonctionnera en mode invisible. Vous n'aurez qu'à utiliser le raccourci **CyberScan Admin** pour superviser le parc !

### Installation depuis les sources (Développement)
```bash
# Cloner le repository
git clone https://github.com/CHARMANTBISSEMOU/CyberScan.git
cd CyberScan

# Créer un environnement virtuel
python -m venv venv
venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Générer les certificats SSL
python generate_certs.py
```

---

## 📖 Utilisation

1. **Démarrage Admin** : Lancez le raccourci `CyberScan Admin` sur le bureau.
2. **Onboarding Wizard** : Lors du premier démarrage, l'assistant vous invitera à renseigner :
   - Vos clés d'API (Groq / Claude).
   - Le numéro de téléphone pour les alertes WhatsApp.
3. **Déploiement de l'Agent** : Lancez `CyberScan Agent` sur la machine à surveiller. Il se placera en arrière-plan et s'allumera à chaque démarrage de Windows.
4. **Analyse IA** : L'IA compile les logs en paquets intelligents (chunking) et vous génère un rapport de remédiation en français clair.

---

## 🔐 Sécurité et Conformité

- **Chiffrement des Données** : Les bases SQLite (clés d'API, etc.) sont chiffrées localement avec AES-256-GCM et un mot de passe maître sécurisé par PBKDF2 (100 000 itérations).
- **Conformité RGPD** : Les données restent en local (LAN). Seuls les logs formatés et anonymisés sont envoyés aux API LLM.
- **Cache SHA-256** : Évite d'envoyer deux fois les mêmes données à l'IA si la configuration de la machine n'a pas changé.

---

## 👤 Auteur et Remerciements

**Développé par BISSEMOU CHARMANT**

<p align="left">
  <a href="https://github.com/CHARMANTBISSEMOU">
    <img src="https://img.shields.io/badge/GitHub-CHARMANTBISSEMOU-black?style=for-the-badge&logo=github" />
  </a>
</p>

### 🙏 Remerciements Académiques (KEYCE Informatique)
Ce projet n'aurait pas pu voir le jour sans les enseignements théoriques et pratiques de mes professeurs :
- **M. DJIONANG Berlin** (Introduction à la cybersécurité)
- **M. OLE SO’ONO Georges Léa** (CCNA 1 : Introduction aux réseaux)
- **M. FOMEKONG Evaris** (Fondamentaux de la programmation en langage Python)
- **M. BALLA MEKONGO Joseph Aubin** (Architecture des Réseaux & Base de l'administration Windows)
- **M. DIFFOUO TAZO Evariste** (Projet tuteuré 1 : Méthodologie et gestion de projet)

### 🛠️ Remerciements Techniques
- **Groq Inc. / Anthropic** pour les API d'intelligence artificielle ultra-rapides.
- **Green API** pour la passerelle WhatsApp.
- **Python Software Foundation** & **Qt Company**.
- La communauté open-source Inno Setup et PyInstaller.

---

## 📄 Licence

Ce projet est sous licence **MIT**.
