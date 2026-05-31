# 🔒 CYBERSCAN

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/PyQt6-0078D4?style=for-the-badge&logo=qt&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-AES--256--green?style=for-the-badge&logo=shield&logoColor=white" />
  <img src="https://img.shields.io/badge/AI-Groq%20%7C%20Claude-purple?style=for-the-badge&logo=artificial-intelligence&logoColor=white" />
  <img src="https://img.shields.io/badge/WebSocket-SSL%2FTLS-orange?style=for-the-badge&logo=websocket&logoColor=white" />
</p>

<p align="center">
  <b>Système d'Audit et de Surveillance de Sécurité Informatique piloté par Intelligence Artificielle</b>
</p>

---

## 📋 Table des Matières

- [Introduction](#introduction)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Sécurité](#sécurité)
- [Configuration API IA](#configuration-api-ia)
- [Captures d'Écran](#captures-décran)
- [Documentation](#documentation)
- [Auteur](#auteur)
- [Licence](#licence)

---

## 🎯 Introduction

**CyberScan** est une solution complète d'audit et de surveillance de sécurité informatique, combinant architecture distribuée, intelligence artificielle et chiffrement de niveau militaire.

### Points Forts

- 🌐 **Architecture Agent-Serveur** avec communication WebSocket SSL/TLS temps réel
- 🤖 **Intelligence Artificielle intégrée** (Groq Llama 3 & Claude Anthropic)
- 🎨 **Double Interface** : Mode Simple (décisionnel) et Mode Expert (technique)
- 🔒 **Chiffrement AES-256-GCM** avec PBKDF2 pour la protection des données
- 📊 **Surveillance réseau** en temps réel avec détection comportementale
- 🇫🇷 **Application 100% francisée** avec support vocal
- 📄 **Rapports PDF** générés automatiquement

---

## ✨ Fonctionnalités

### 🖥️ Console d'Administration

| Fonctionnalité | Description |
|---------------|-------------|
| **Dashboard Synthétique** | Vue d'ensemble du parc avec scores de sécurité |
| **Scan Réseau** | Découverte automatique des équipements et scan de ports |
| **Monitoring Trafic** | Surveillance temps réel des connexions et alertes |
| **Analyse IA** | Évaluation des vulnérabilités avec recommandations |
| **Rapports PDF** | Export professionnel des résultats d'audit |
| **Onboarding Wizard** | Assistant de configuration guidé |

### 🛡️ Agent Windows

| Fonctionnalité | Description |
|---------------|-------------|
| **Auto-démarrage** | Lancement automatique avec Windows (Registre) |
| **Collecte WMI** | Métriques système en temps réel |
| **Scan Ports** | Modes Quick (<20s) et Full (60-90s) |
| **Intégrité Fichiers** | Surveillance des fichiers critiques |
| **Analyse Logs** | Détection d'anomalies dans les Event Logs |
| **Communication Sécurisée** | WebSocket SSL avec reconnexion auto |

### 🤖 Intelligence Artificielle

- **Analyse Contextuelle** : Interprétation intelligente des vulnérabilités
- **Recommandations** : Suggestions d'actions prioritaires en français
- **Scores de Sécurité** : Évaluation 0-100 avec codes couleur
- **Rapports Naturels** : Explications compréhensibles pour tous

---

## 🏗️ Architecture

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
│  │ • Network Scan   │         │ • Port Scan      │          │
│  │ • Traffic Monitor│         │ • File Integrity │          │
│  │ • AI Analysis    │         │ • Event Log      │          │
│  └────────┬─────────┘         └──────────────────┘          │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │   SQLITE DB      │         │   AI SERVICES    │          │
│  │  (cyberscan.db)  │         │  • Groq API      │          │
│  │                  │         │  • Claude API    │          │
│  │ • machines       │         │                  │          │
│  │ • scans          │         │ Analysis &       │          │
│  │ • api_keys       │         │ Recommendations│          │
│  │ • traffic_alerts │         │                  │          │
│  └──────────────────┘         └──────────────────┘          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Technologies Utilisées

| Couche | Technologie |
|--------|-------------|
| Interface | Python 3.12 + PyQt6 |
| Communication | WebSocket + SSL/TLS 1.3 |
| Base de données | SQLite 3 |
| Chiffrement | AES-256-GCM + PBKDF2 |
| IA/ML | Groq API + Claude API |
| Système | WMI + psutil + win32api |
| Packaging | PyInstaller |

---

## 🚀 Installation

### Prérequis

- Windows 10/11 (64-bit)
- Python 3.12+
- Connexion Internet (pour l'analyse IA)

### Installation depuis les sources

```bash
# Cloner le repository
git clone https://github.com/CHARMANTBISSEMOU/CyberScan.git
cd CyberScan

# Créer un environnement virtuel
python -m venv venv
venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Générer les certificats SSL (développement)
python generate_certs.py
```

### Installation via exécutables

Les binaires précompilés sont disponibles dans le dossier `CyberScan_Final_v2.1_Simple/` :

```
CyberScan_Final_v2.1_Simple/
├── CyberScan.exe          # Console d'Administration
└── CyberScanAgent.exe     # Agent Windows
```

---

## 📖 Utilisation

### Démarrage Rapide

#### 1. Lancer la Console d'Administration

```bash
cd cyberscan_admin
python app.py
```

Ou exécutez directement : `CyberScan.exe`

#### 2. Déployer l'Agent Windows

Sur chaque machine du parc à surveiller :

```bash
# Copier CyberScanAgent.exe sur la machine cible
# L'agent s'installera automatiquement au démarrage
CyberScanAgent.exe
```

#### 3. Configuration Initiale

Lors du premier démarrage, le **Wizard d'Onboarding** vous guidera :

1. ✅ Configuration réseau (IP et port du serveur)
2. ✅ Saisie des clés API (Groq et/ou Claude)
3. ✅ Validation des connexions
4. ✅ Choix du mode interface (Simple ou Expert)
5. ✅ Premier scan test

### Mode Simple vs Mode Expert

| Mode Simple | Mode Expert |
|-------------|-------------|
| Dashboard synthétique | Analyses techniques détaillées |
| Scores visuels 0-100 | Logs bruts et métriques |
| Actions rapides | Configuration avancée |
| Parfait pour décideurs | Conçu pour administrateurs |

### Commandes Utiles

```bash
# Scan rapide d'une machine
# Via l'interface : Onglet Machines → Clic droit → Scan Rapide

# Export PDF d'un rapport
# Via l'interface : Bouton "Exporter PDF"

# Voir le trafic en temps réel
# Via l'interface : Onglet Trafic
```

---

## 🔐 Sécurité

### Chiffrement des Données

CyberScan implémente des standards de chiffrement de niveau militaire :

| Paramètre | Valeur |
|-----------|--------|
| Algorithme | AES-256-GCM |
| Taille clé | 256 bits (NSA TOP SECRET) |
| Mode | Galois/Counter Mode (authentifié) |
| Dérivation | PBKDF2-HMAC-SHA256 |
| Itérations | 100 000 (OWASP 2024) |
| Sel | 16 bytes aléatoire par machine |

### Conformité RGPD

- ✅ **100% Local** : Aucune donnée personnelle ne quitte le réseau
- ✅ **Chiffrement** : Toutes les données sensibles sont chiffrées
- ✅ **Contrôle** : L'utilisateur contrôle totalement ses données
- ✅ **Transparence** : Aucune télémétrie ou analytics tiers

### Bonnes Pratiques

- Communication SSL/TLS 1.3 obligatoire
- Timeout sur toutes les connexions réseau
- Gestion sécurisée des erreurs
- Sanitization des entrées utilisateur

---

## 🔑 Configuration API IA

### Groq API

1. Créer un compte sur [console.groq.com](https://console.groq.com)
2. Générer une clé API
3. Format : `gsk_...`

### Claude API (Anthropic)

1. Créer un compte sur [console.anthropic.com](https://console.anthropic.com)
2. Générer une clé API
3. Format : `sk-ant-...`

### Configuration dans CyberScan

1. Lancez l'application
2. Suivez le **Wizard d'Onboarding**
3. Entrez vos clés API aux étapes correspondantes
4. Cliquez sur "Tester" pour valider

---

## 📸 Captures d'Écran

### Mode Simple - Dashboard

```
[À AJOUTER : Capture écran dashboard Mode Simple]
```

### Mode Expert - Analyse Technique

```
[À AJOUTER : Capture écran Mode Expert avec onglets]
```

### Onboarding Wizard

```
[À AJOUTER : Capture écran assistant configuration]
```

### Surveillance Trafic

```
[À AJOUTER : Capture écran monitoring réseau]
```

### Rapport PDF Généré

```
[À AJOUTER : Capture écran exemple rapport PDF]
```

---

## 📚 Documentation

### Documentation Complète

Le **Cahier des Charges** complet est disponible dans le dossier `presentation/` :

```
presentation/
└── CAHIER_CHARGES_PART1.md    # Documentation détaillée
```

Contenu :
- Architecture technique détaillée
- Spécifications fonctionnelles
- Budget et planification
- Références bibliographiques

### Structure du Projet

```
CyberScan/
├── cyberscan_admin/          # Console d'Administration
│   ├── app.py               # Interface principale
│   ├── server.py            # Serveur WebSocket
│   ├── database.py          # Gestion SQLite
│   ├── crypto_utils.py      # Chiffrement AES-256-GCM
│   ├── ia_analyzer.py       # Intégration IA
│   └── ...
│
├── cyberscan_agent/          # Agent Windows
│   ├── agent_enhanced.py    # Agent principal
│   ├── win_scanner.py       # Scanner système
│   ├── port_scanner.py      # Scanner ports
│   └── ...
│
├── presentation/            # Documentation
│   └── CAHIER_CHARGES_PART1.md
│
├── certs/                   # Certificats SSL
├── requirements.txt         # Dépendances Python
├── README.md               # Ce fichier
└── .gitignore              # Fichiers ignorés
```

---

## 👤 Auteur

**Développé par BISSEMOU CHARMANT**

<p align="center">
  <a href="https://github.com/CHARMANTBISSEMOU">
    <img src="https://img.shields.io/badge/GitHub-CHARMANTBISSEMOU-black?style=for-the-badge&logo=github" />
  </a>
</p>

---

## 📄 Licence

Ce projet est sous licence **MIT**.

```
MIT License

Copyright (c) 2026 BISSEMOU CHARMANT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
```

---

## 🙏 Remerciements

- **Groq Inc.** pour l'API Llama 3
- **Anthropic** pour l'API Claude
- **Python Software Foundation**
- **Qt Company** pour PyQt6
- Communauté open source

---

<p align="center">
  <b>🔒 CYBERSCAN - Sécurité et Intelligence Artificielle au service de la protection informatique</b>
</p>
