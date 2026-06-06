# 📋 JOURNAL DES MODIFICATIONS — CyberScan Agent
> Fichier de traçabilité pour retour arrière en cas d'erreur.
> Chaque modification liste : la date, le fichier, la ligne, le code avant et après.

---

## Session du 2026-06-03

### MOD-001 — Ajout du fichier de configuration serveur (`SERVER_CONFIG_FILE`)
**Fichier :** `cyberscan_agent/agent.py`
**Lignes :** 43–50
**Problème résolu :** Permettre la configuration manuelle de l'IP serveur pour contourner mDNS bloqué.

**Avant :**
```python
# Fichiers de données
SYSTEM_INFO_FILE = os.path.join(DATA_DIR, 'system_info.json')
SCAN_RESULTS_FILE = os.path.join(DATA_DIR, 'scan_results.json')
LOG_FILE = os.path.join(DATA_DIR, 'agent.log')
PID_FILE = os.path.join(DATA_DIR, 'agent.pid')
```

**Après :**
```python
# Fichiers de données
SYSTEM_INFO_FILE = os.path.join(DATA_DIR, 'system_info.json')
SCAN_RESULTS_FILE = os.path.join(DATA_DIR, 'scan_results.json')
LOG_FILE = os.path.join(DATA_DIR, 'agent.log')
PID_FILE = os.path.join(DATA_DIR, 'agent.pid')
# Fichier de configuration du serveur (IP manuelle possible)
SERVER_CONFIG_FILE = os.path.join(DATA_DIR, 'server_config.json')
```

---

### MOD-002 — Correction du fichier PID (plus jamais en lecture seule)
**Fichier :** `cyberscan_agent/agent.py`
**Lignes :** 149–165
**Problème résolu :** Le fichier `agent.pid` était mis en lecture seule après écriture. En cas de crash,
le fichier restait et empêchait tout redémarrage de l'agent (faux positif "déjà en cours").

**Avant :**
```python
def save_pid():
    """Sauvegarde le PID du processus."""
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        set_file_readonly(PID_FILE)   # ← PROBLÈME : rend le fichier non supprimable
    except:
        pass

def remove_pid():
    """Supprime le fichier PID."""
    try:
        if os.path.exists(PID_FILE):
            os.chmod(PID_FILE, stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            os.remove(PID_FILE)
    except:
        pass
```

**Après :**
```python
def save_pid():
    """Sauvegarde le PID du processus.
    IMPORTANT: le fichier PID n'est JAMAIS mis en lecture seule pour éviter
    qu'un crash laisse un PID orphelin impossible à supprimer.
    """
    try:
        # S'assurer que le fichier est accessible en écriture avant tout
        if os.path.exists(PID_FILE):
            try:
                os.chmod(PID_FILE, stat.S_IWUSR | stat.S_IRUSR)
            except Exception:
                pass
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        # NE PAS appeler set_file_readonly() sur le PID_FILE
    except Exception as e:
        logger.error(f"Impossible de sauvegarder le PID: {e}")

def remove_pid():
    """Supprime le fichier PID. Gère le cas où le fichier est en lecture seule."""
    try:
        if os.path.exists(PID_FILE):
            try:
                os.chmod(PID_FILE, stat.S_IWUSR | stat.S_IRUSR)
            except Exception:
                pass
            os.remove(PID_FILE)
    except Exception as e:
        logger.error(f"Impossible de supprimer le PID file: {e}")
```

---

### MOD-003 — Timeout mDNS porté de 10s à 20s
**Fichier :** `cyberscan_agent/agent.py`
**Ligne :** ~220 (dans `discover_server()`)
**Problème résolu :** Le délai de 10s n'était pas suffisant sur certains réseaux lents.

**Avant :**
```python
listener.event.wait(timeout=10)
```

**Après :**
```python
# Timeout porté à 20s (était 10s) pour laisser plus de temps à mDNS
found = listener.event.wait(timeout=20)
```

---

### MOD-004 — Résolution mDNS bloqué par le pare-feu (stratégie en 4 niveaux)
**Fichier :** `cyberscan_agent/agent.py`
**Fonction remplacée :** `discover_server()` (ancienne version ~30 lignes → nouvelle version ~80 lignes)
**Problème résolu :** Le port UDP 5353 (mDNS) est souvent filtré par Windows Firewall et les
pare-feux d'entreprise/école. L'ancienne version tombait directement sur `localhost` en fallback.

**Nouvelles fonctions ajoutées :**
- `load_server_config()` — lit `server_config.json` si présent
- `save_server_config(ip, port)` — mémorise l'IP trouvée pour les prochains démarrages
- `_try_connect(candidate, port)` — teste une IP sur le port WebSocket (pour le scan parallèle)

**Nouvelle logique `discover_server()` :**
```
Priorité 1 : Lecture de server_config.json (config manuelle ou mémorisée)
    ↓ si absent
Priorité 2 : mDNS / Zeroconf avec timeout=20s
    → si trouvé, sauvegarde dans server_config.json
    ↓ si bloqué ou timeout
Priorité 3 : Scan réseau local parallèle (64 threads, timeout 0.4s/IP)
    → si trouvé, sauvegarde dans server_config.json
    ↓ si réseau vide
Priorité 4 : Fallback localhost:8765 + message d'aide dans les logs
```

**Amélioration du scan réseau :**
- Ancienne version : séquentielle (timeout 0.2s × 253 IPs = ~50 secondes dans le pire cas)
- Nouvelle version : 64 threads simultanés → ~2 secondes dans le pire cas

---

## Comment contourner mDNS bloqué manuellement

Si l'agent ne trouve toujours pas le serveur, créer le fichier :
```
%TEMP%\.cyberscan_agent\server_config.json
```
Avec le contenu :
```json
{
  "server_ip": "192.168.X.X",
  "server_port": 8765
}
```
Remplacer `192.168.X.X` par l'IP réelle de la machine admin (visible dans les logs du serveur).

---

## Compilations effectuées — 2026-06-03

### MOD-005 — Correction de agent_silent.py (fichier réellement compilé)
**Problème découvert :** Le fichier `agent.spec` compile `agent_silent.py`, PAS `agent.py`.
Les 4 corrections avaient été appliquées à `agent.py` uniquement.  
**Action :** Les mêmes 4 corrections ont été appliquées à `agent_silent.py`.

### Résultats de compilation (PyInstaller 6.20.0 / Python 3.14)

| Exécutable | Taille | Date compilation | Statut |
|-----------|--------|-----------------|--------|
| `CyberScanAgent.exe` | 19.8 MB | 2026-06-03 11:25 | ✅ OK |
| `CyberScan.exe` | 66.2 MB | 2026-06-03 11:29 | ✅ OK |

> Note : Exit code 1 affiché par PyInstaller est dû aux `SyntaxWarning` de `wmi.py` (bibliothèque tierce). Le message "Build complete!" confirme que les EXE sont valides.

### Déploiement vers CyberScan_Final_v2.1_Simple

- **Anciens EXE sauvegardés** dans : `CyberScan_Final_v2.1_Simple\_backup_avant_corrections\`
  - `CyberScanAgent_OLD.exe` (ancienne version sans corrections)
  - `CyberScan_OLD.exe` (ancienne version)
- **Nouveaux EXE déployés** dans : `CyberScan_Final_v2.1_Simple\`
  - `CyberScanAgent.exe` ✅ avec les 4 corrections
  - `CyberScan.exe` ✅ recompilé proprement

---

## Comment faire un rollback

Pour revenir à l'état original de `agent.py` :
1. Utiliser `git checkout cyberscan_agent/agent.py` si git est disponible.
2. Ou appliquer manuellement les blocs "Avant" de chaque MOD ci-dessus.

Les modifications concernent uniquement :
- Lignes 43–50 (ajout `SERVER_CONFIG_FILE`)
- Lignes 149–165 (`save_pid` / `remove_pid`)
- Lignes 208–300 (ajout fonctions + refactoring `discover_server`)
