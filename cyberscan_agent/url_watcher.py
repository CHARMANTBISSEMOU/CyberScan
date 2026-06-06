"""
CyberScan URL Watcher
=====================
Surveille l'historique de navigation toutes les 3 minutes.
Compare les URLs nouvellement visitées à une liste de domaines dangereux.
Déclenche une alerte immédiate si une URL suspecte est détectée.

Fonctionne en arrière-plan (thread daemon) dans l'agent silencieux.
"""

import ctypes
import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import sys
import json
import urllib.request
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Copie partagée (lecture même fichier verrouillé par navigateur) ──
_GENERIC_READ = 0x80000000
_FILE_SHARE_RW = 0x00000001 | 0x00000002
_OPEN_EXISTING = 3
_FLAG_SEQ = 0x08000000

def _copy_locked_file(src: str, dst: str) -> bool:
    """Copie un fichier verrouillé (ex: historique navigateur) via Win32 CreateFile."""
    k32 = ctypes.windll.kernel32
    INVALID = ctypes.c_void_p(-1).value
    h = k32.CreateFileW(src, _GENERIC_READ, _FILE_SHARE_RW, None, _OPEN_EXISTING, _FLAG_SEQ, None)
    if h == INVALID:
        return False
    try:
        buf = ctypes.create_string_buffer(1 << 20)
        br = ctypes.c_ulong(0)
        with open(dst, 'wb') as f:
            while True:
                ok = k32.ReadFile(h, buf, len(buf), ctypes.byref(br), None)
                if not ok or br.value == 0:
                    break
                f.write(buf.raw[:br.value])
        return True
    except Exception:
        return False
    finally:
        k32.CloseHandle(h)

# ─────────────────────────────────────────────────────────────────
# BASE DE DONNÉES DES DOMAINES SUSPECTS (locale, sans API)
# Classée par catégorie et niveau de risque
# ─────────────────────────────────────────────────────────────────
RISKY_PATTERNS = {
    "CRITIQUE": {
        "label": "Site de téléchargement illégal / Torrent",
        "patterns": [
            r"torrent", r"thepiratebay", r"1337x", r"rarbg", r"kickass",
            r"yts\.m", r"limetorrent", r"torrent9", r"cpasbien", r"yggtorrent",
            r"wawacity", r"zone-telechargement", r"dl-protect", r"filmyzilla",
            r"crack", r"serial[\-_]?key", r"keygen", r"warez", r"nulled",
            r"cracked\.", r"hackforums", r"darkweb", r"\.onion",
        ]
    },
    "CRITIQUE_PHISHING": {
        "label": "Site de phishing / Hameçonnage",
        "patterns": [
            r"paypa[l1]-", r"faceb[o0][o0]k-login", r"apple-id-verify",
            r"microsoft-support-alert", r"amazon-security-update",
            r"login-secure-[a-z]+\.com", r"verify-account-",
            r"account-suspended-", r"update-your-payment",
            r"free-gift-claim", r"you-have-won",
        ]
    },
    "ÉLEVÉ": {
        "label": "Outil de contrôle à distance non autorisé",
        "patterns": [
            r"anydesk\.com/download", r"teamviewer\.com/download",
            r"ultraviewer", r"ammyy", r"supremo\.biz",
            r"logmein\.com", r"gotomypc",
        ]
    },
    "ÉLEVÉ_PROXY": {
        "label": "Proxy / Contournement de sécurité",
        "patterns": [
            r"proxy[\-_]?free", r"hide\.me", r"anonymousproxy",
            r"unblocksite", r"proxysite\.com", r"kproxy",
            r"hidemyass", r"ninja-cloak", r"zendproxy",
        ]
    },
    "MOYEN": {
        "label": "Navigation non sécurisée (HTTP)",
        # Vérifié différemment (scheme HTTP) — voir _check_url_risk()
        "patterns": []
    },
}

# Chemins d'accès sécurisés sans nécessiter les droits admin
import tempfile
def _get_watcher_dir():
    for base in [
        os.environ.get('APPDATA', ''),
        os.environ.get('PROGRAMDATA', r'C:\ProgramData'),
        tempfile.gettempdir()
    ]:
        if not base: continue
        candidate = os.path.join(base, 'CyberScan')
        try:
            os.makedirs(candidate, exist_ok=True)
            test_file = os.path.join(candidate, '.write_test_watcher')
            with open(test_file, 'w') as f: f.write('ok')
            os.unlink(test_file)
            return candidate
        except Exception:
            continue
    return tempfile.gettempdir()

_LOG_DIR = _get_watcher_dir()
_SEEN_URLS_FILE = os.path.join(_LOG_DIR, '.cs_seen_urls.json')

_watcher_thread = None
_watcher_stop = threading.Event()
_watcher_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────
# Gestion des URLs déjà vues (pour ne pas réenvoyer les alertes)
# ─────────────────────────────────────────────────────────────────
def _load_seen_urls() -> set:
    """Charge l'ensemble des URLs déjà alertées."""
    import json, base64
    try:
        if os.path.exists(_SEEN_URLS_FILE):
            with open(_SEEN_URLS_FILE, 'r') as f:
                data = json.loads(base64.b64decode(f.read()).decode())
            # Ne garder que les URLs des dernières 24h pour éviter la croissance infinie
            cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
            return {url for url, ts in data.items() if ts > cutoff}
    except Exception:
        pass
    return set()


def _save_seen_urls(seen: set):
    """Sauvegarde les URLs alertées avec leur timestamp."""
    import json, base64
    try:
        os.makedirs(_LOG_DIR, exist_ok=True)
        now = datetime.now().isoformat()
        data = {url: now for url in seen}
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        with open(_SEEN_URLS_FILE, 'w') as f:
            f.write(encoded)
    except Exception as e:
        logger.debug(f"Sauvegarde seen_urls : {e}")


# ─────────────────────────────────────────────────────────────────
# IA Embarquée (Groq API) pour générer un message d'alerte contextuel
# ─────────────────────────────────────────────────────────────────
# Remplacez cette valeur par votre clé API Groq ou utilisez une variable d'environnement
GROQ_API_KEY = "VOTRE_CLE_API_GROQ_ICI"

def generate_groq_alert(url: str, label: str, machine_name: str) -> str:
    """Génère un message très percutant via l'IA Groq selon l'URL."""
    try:
        url_api = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        }
        prompt = (f"Le poste '{machine_name}' vient d'ouvrir l'URL dangereuse suivante : {url}. "
                  f"Ce site est classé comme '{label}'. Rédige un court message WhatsApp d'alerte très percutant et "
                  f"professionnel (max 3 phrases) pour prévenir l'administrateur du danger. "
                  f"CONSIGNE STRICTE : Ton message DOIT obligatoirement commencer par mentionner clairement le poste concerné (ex: 'Alerte : Le poste {machine_name} a accédé...'). "
                  f"N'utilise pas le mot 'employé'. N'inclus pas de salutations ni de formules de politesse de fin. Va droit au but, sois très alarmiste. Utilise 2 ou 3 emojis pertinents.")
        
        data = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 150
        }
        
        req = urllib.request.Request(url_api, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as response:
            res_json = json.loads(response.read().decode("utf-8"))
            return res_json["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.error(f"Erreur API Groq : {e}")
        return None

# ─────────────────────────────────────────────────────────────────
# Vérification d'une URL
# ─────────────────────────────────────────────────────────────────
def _check_url_risk(url: str) -> tuple[str, str] | None:
    """
    Vérifie si une URL est dangereuse.

    Returns:
        (risk_level, label) si dangereuse, None sinon
    """
    url_lower = url.lower()

    # 1. Vérification avec Sensibilité à 90% (Liste noire dynamique danger.txt)
    try:
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        parent_dir = os.path.dirname(base_dir)
        possible_paths = [
            os.path.join(base_dir, "danger.txt"),
            os.path.join(parent_dir, "danger.txt")
        ]
        for p in possible_paths:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith("#"):
                            if domain in url_lower:
                                return "CRITIQUE", "Site dangereux (Liste Noire de 100+ sites)"
                break
    except Exception as e:
        logger.error(f"Erreur lecture danger.txt: {e}")

    # 2. Vérification Regex classique
    for risk_key, info in RISKY_PATTERNS.items():
        for pattern in info["patterns"]:
            if re.search(pattern, url_lower):
                # Normaliser le niveau de risque
                level = risk_key.split("_")[0]  # "CRITIQUE_PHISHING" → "CRITIQUE"
                return level, info["label"]

    # HTTP non chiffré (hors localhost et IPs locales)
    if url_lower.startswith("http://"):
        domain = url_lower.replace("http://", "").split("/")[0].split(":")[0]
        local_prefixes = ("localhost", "127.", "192.168.", "10.", "172.")
        if not any(domain.startswith(p) for p in local_prefixes):
            return "MOYEN", "Navigation non chiffrée (HTTP)"

    return None


# ─────────────────────────────────────────────────────────────────
# Lecture de l'historique récent (3 dernières minutes)
# ─────────────────────────────────────────────────────────────────
def _get_recent_urls(minutes: int = 3) -> list[dict]:
    """
    Lit les URLs visitées dans les N dernières minutes
    depuis Chrome, Edge, Firefox, Brave.
    """
    results = []
    since = datetime.now() - timedelta(minutes=minutes)
    localappdata = os.environ.get('LOCALAPPDATA', '')

    # ── Chrome-based (Chrome, Edge, Brave) ──────────────────────
    chrome_epoch = datetime(1601, 1, 1)
    since_utc = datetime.utcnow() - timedelta(minutes=minutes)
    since_chrome = int((since_utc - chrome_epoch).total_seconds() * 1_000_000)

    chromium_paths = []
    if localappdata:
        chromium_paths = [
            (os.path.join(localappdata, 'Google', 'Chrome', 'User Data', 'Default', 'History'), 'Chrome'),
            (os.path.join(localappdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'History'), 'Edge'),
            (os.path.join(localappdata, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History'), 'Brave'),
        ]

    for hist_path, browser in chromium_paths:
        if not os.path.exists(hist_path):
            continue
        tmp = os.path.join(_LOG_DIR, f'.watcher_tmp_{browser.lower()}')
        try:
            os.makedirs(_LOG_DIR, exist_ok=True)
            # Copie partagée : fonctionne même quand le navigateur est ouvert
            copied = _copy_locked_file(hist_path, tmp)
            if not copied:
                try:
                    shutil.copy2(hist_path, tmp)
                except (PermissionError, OSError):
                    continue
            conn = sqlite3.connect(tmp, timeout=3)
            conn.text_factory = str
            cur = conn.cursor()
            cur.execute(
                "SELECT url, title, last_visit_time FROM urls "
                "WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT 50",
                (since_chrome,)
            )
            for url, title, vt in cur.fetchall():
                try:
                    dt = chrome_epoch + timedelta(microseconds=vt)
                    visited_at = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    visited_at = "?"
                results.append({"browser": browser, "url": url[:300],
                                 "title": (title or "")[:100], "visited_at": visited_at})
            conn.close()
        except Exception as e:
            logger.debug(f"URL watcher {browser}: {e}")
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    # ── Firefox ─────────────────────────────────────────────────
    appdata = os.environ.get('APPDATA', '')
    profiles_dir = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
    if os.path.exists(profiles_dir):
        since_ff = int(since.timestamp() * 1_000_000)
        for profile in os.listdir(profiles_dir):
            places = os.path.join(profiles_dir, profile, 'places.sqlite')
            if not os.path.exists(places):
                continue
            tmp = os.path.join(_LOG_DIR, '.watcher_tmp_firefox')
            try:
                # Copie partagée : fonctionne même quand Firefox est ouvert
                copied = _copy_locked_file(places, tmp)
                if not copied:
                    try:
                        shutil.copy2(places, tmp)
                    except (PermissionError, OSError):
                        continue
                conn = sqlite3.connect(tmp, timeout=3)
                cur = conn.cursor()
                cur.execute(
                    "SELECT p.url, p.title, h.visit_date "
                    "FROM moz_places p JOIN moz_historyvisits h ON p.id = h.place_id "
                    "WHERE h.visit_date > ? ORDER BY h.visit_date DESC LIMIT 50",
                    (since_ff,)
                )
                for url, title, vt in cur.fetchall():
                    try:
                        dt = datetime.fromtimestamp(vt / 1_000_000)
                        visited_at = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        visited_at = "?"
                    results.append({"browser": "Firefox", "url": url[:300],
                                     "title": (title or "")[:100], "visited_at": visited_at})
                conn.close()
            except Exception as e:
                logger.debug(f"URL watcher Firefox: {e}")
            finally:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

    return results


# ─────────────────────────────────────────────────────────────────
# Boucle principale du watcher
# ─────────────────────────────────────────────────────────────────
def _watcher_loop(interval_seconds: int = 180):
    """
    Boucle de surveillance des URLs — s'exécute toutes les `interval_seconds` secondes.
    Par défaut : 180 secondes (3 minutes).
    """
    import socket as _socket
    hostname = _socket.gethostname()

    logger.error(f"[URL Watcher] Démarré — cycle toutes les {interval_seconds}s")

    seen_urls = _load_seen_urls()

    while not _watcher_stop.is_set():
        try:
            logger.info("[URL Watcher] Analyse de l'historique de navigation en cours... (en parallèle)")
            recent = _get_recent_urls(minutes=max(interval_seconds // 60 + 1, 4))
            logger.info(f"[URL Watcher] -> {len(recent)} URLs récentes trouvées dans les navigateurs.")
            if recent:
                sample = [r['url'][:60] + "..." for r in recent[:2]]
                logger.info(f"[URL Watcher] -> Exemples scannés : {sample}")
                
            alerts_sent = 0

            for entry in recent:
                url = entry.get('url', '')
                if not url or url in seen_urls:
                    continue

                risk_result = _check_url_risk(url)
                if risk_result:
                    risk_level, label = risk_result
                    logger.error(
                        f"[URL Watcher] URL SUSPECTE détectée ({risk_level})\n"
                        f"  Machine : {hostname}\n"
                        f"  URL     : {url}\n"
                        f"  Type    : {label}\n"
                        f"  Browser : {entry.get('browser')}\n"
                        f"  Heure   : {entry.get('visited_at')}"
                    )

                    # Marquer comme vu avant l'envoi (évite les doublons si l'envoi plante)
                    seen_urls.add(url)
                    _save_seen_urls(seen_urls)

                    # Génération du message via Groq
                    ai_msg = generate_groq_alert(url, label, hostname)
                    if ai_msg:
                        logger.error(f"[URL Watcher] Message IA généré : {ai_msg}")

                    # Envoyer l'alerte sur tous les canaux configurés
                    try:
                        from alert_sender import send_alert
                        results = send_alert(
                            alert_type=label,
                            url=url,
                            machine_name=hostname,
                            risk_level=risk_level,
                            custom_message=ai_msg
                        )
                        alerts_sent += 1
                        logger.error(f"[URL Watcher] Alerte envoyée : {results}")
                    except Exception as e:
                        logger.error(f"[URL Watcher] Erreur envoi alerte : {e}")

            if alerts_sent > 0:
                logger.error(f"[URL Watcher] {alerts_sent} alerte(s) envoyée(s) ce cycle")

        except Exception as e:
            logger.error(f"[URL Watcher] Erreur cycle : {e}")

        # Attendre jusqu'au prochain cycle
        _watcher_stop.wait(interval_seconds)

    logger.error("[URL Watcher] Arrêté proprement")


# ─────────────────────────────────────────────────────────────────
# API publique
# ─────────────────────────────────────────────────────────────────
def start_url_watcher(interval_seconds: int = 180):
    """
    Démarre le watcher d'URLs en arrière-plan.

    Args:
        interval_seconds: Intervalle de vérification (défaut: 180s = 3 minutes)
    """
    global _watcher_thread
    with _watcher_lock:
        if _watcher_thread and _watcher_thread.is_alive():
            logger.debug("[URL Watcher] Déjà actif, rien à faire")
            return
        _watcher_stop.clear()
        _watcher_thread = threading.Thread(
            target=_watcher_loop,
            args=(interval_seconds,),
            daemon=True,
            name="CyberScan-URLWatcher"
        )
        _watcher_thread.start()
        logger.error(f"[URL Watcher] Thread démarré (id={_watcher_thread.ident})")


def stop_url_watcher():
    """Arrête proprement le watcher d'URLs."""
    _watcher_stop.set()
    if _watcher_thread:
        _watcher_thread.join(timeout=5)
    logger.error("[URL Watcher] Thread arrêté")


def test_url(url: str) -> None:
    """Teste manuellement si une URL serait détectée comme suspecte."""
    result = _check_url_risk(url)
    if result:
        level, label = result
        print(f"⚠️  DÉTECTÉ — Niveau: {level} | Catégorie: {label}")
    else:
        print(f"✅ URL considérée sûre : {url}")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    if len(sys.argv) > 1:
        # Test d'une URL spécifique
        test_url(sys.argv[1])
    else:
        # Démo : affiche les URLs récentes et leur niveau de risque
        print("=== Test URL Watcher — Analyse des 5 dernières minutes ===\n")
        urls = _get_recent_urls(5)
        if not urls:
            print("Aucune URL récente trouvée.")
        for entry in urls:
            risk = _check_url_risk(entry['url'])
            tag = f"⚠️  {risk[0]} — {risk[1]}" if risk else "✅ OK"
            print(f"[{entry['browser']}] {tag}\n  {entry['url'][:80]}\n")
