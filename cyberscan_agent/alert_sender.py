"""
CyberScan Alert Sender
======================
Envoie des alertes de sécurité via :
  - WhatsApp  (Green API — gratuit 3 mois, scan QR code de ton propre numéro)
  - Email     (SMTP Gmail / Outlook / autre)
  - WebSocket (notification vers l'admin — popup Windows)

Configuration stockée dans server_config.json sous la clé "alerts".
"""

import json
import logging
import os
import socket
import smtplib
import urllib.request
import urllib.parse
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Chargement de la config depuis alert_config.json
# ─────────────────────────────────────────────

# Cache mémoire de la config (mise à jour par reload_config)
_cached_alert_config = {}

def _find_alert_config_file() -> str:
    """Cherche alert_config.json dans les emplacements possibles."""
    import tempfile
    candidates = [
        os.path.join(os.environ.get('APPDATA', ''), 'CyberScan', '.cyberscan_agent', 'alert_config.json'),
        os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'CyberScan', '.cyberscan_agent', 'alert_config.json'),
        os.path.join(tempfile.gettempdir(), 'CyberScan', '.cyberscan_agent', 'alert_config.json'),
        os.path.join(tempfile.gettempdir(), '.cyberscan_agent', 'alert_config.json'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]  # Valeur par défaut même si absent


def _load_alert_config():
    """Charge la configuration des alertes depuis alert_config.json ou le cache mémoire."""
    global _cached_alert_config
    # Si cache mémoire rempli (mis à jour par reload_config), l'utiliser directement
    if _cached_alert_config:
        return _cached_alert_config
    config_path = _find_alert_config_file()
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            logger.error(f"[AlertSender] Config chargée depuis {config_path}")
            return cfg
    except Exception as e:
        logger.error(f"Erreur lecture config alertes : {e}")
    return {}


def reload_config(config: dict):
    """Met à jour le cache mémoire de la config (appelé par agent_silent quand update_config reçu)."""
    global _cached_alert_config
    _cached_alert_config = config
    logger.error(f"[AlertSender] Config alertes mise à jour en mémoire (WA: {config.get('whatsapp', {}).get('enabled')})")



# ─────────────────────────────────────────────
# CANAL 1 : WhatsApp via Green API
# Credentials hardcodés — seul le numéro destinataire est configurable
# ─────────────────────────────────────────────
# Green API — Instance liée au numéro WhatsApp 237690731401
GREEN_API_INSTANCE_ID = "7107642110"
GREEN_API_TOKEN       = "20674f06130f4220a1ad168ce623f2eded510d13e482416bac"
GREEN_API_BASE_URL    = "https://7107.api.greenapi.com"

def send_whatsapp(to_phone: str, message: str,
                  instance_id: str = GREEN_API_INSTANCE_ID,
                  api_token: str = GREEN_API_TOKEN,
                  api_base_url: str = GREEN_API_BASE_URL) -> bool:
    """
    Envoie un message WhatsApp via Green API.

    Args:
        to_phone:    Numéro destinataire format international SANS +
                     suivi de @c.us  ex: "237690123456@c.us"
        message:     Texte du message
        instance_id: (optionnel) Remplace le credential hardcodé
        api_token:   (optionnel) Remplace le credential hardcodé
        api_base_url:(optionnel) URL de base de l'instance Green API

    Returns:
        True si succès, False sinon
    """
    try:
        url = f"{api_base_url}/waInstance{instance_id}/sendMessage/{api_token}"
        body = json.dumps({
            "chatId": to_phone,
            "message": message
        }).encode('utf-8')
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "CyberScan/2.2"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp_body = resp.read().decode('utf-8', errors='ignore')
            if resp.status == 200:
                logger.info(f"WhatsApp Green API envoyé à {to_phone}")
                return True
            else:
                logger.warning(f"WhatsApp Green API HTTP {resp.status}: {resp_body[:200]}")
                return False
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore') if e.fp else ''
        logger.error(f"Erreur Green API HTTP {e.code}: {err_body[:300]}")
        return False
    except Exception as e:
        logger.error(f"Erreur envoi WhatsApp Green API : {e}")
        return False



def format_phone_for_green_api(phone: str) -> str:
    """
    Convertit un numéro de téléphone au format attendu par Green API.

    Exemples :
      "+237 690 123 456" → "237690123456@c.us"
      "00237690123456"   → "237690123456@c.us"
      "237690123456"     → "237690123456@c.us"
    """
    # Supprimer tout ce qui n'est pas un chiffre
    digits = ''.join(c for c in phone if c.isdigit())
    # Supprimer le préfixe international 00 si présent
    if digits.startswith('00'):
        digits = digits[2:]
    # Supprimer le + (déjà fait par isdigit)
    # Ajouter le suffixe Green API
    if not digits.endswith('@c.us'):
        digits = f"{digits}@c.us"
    return digits



# ─────────────────────────────────────────────
# CANAL 2 : Email via SMTP
# ─────────────────────────────────────────────
# Compatible Gmail (SMTP TLS port 587) et Outlook (port 587)
# Pour Gmail : activer "Mots de passe d'application" dans le compte Google

def send_email(smtp_host: str, smtp_port: int, smtp_user: str,
               smtp_pass: str, to_email: str, subject: str, body: str) -> bool:
    """
    Envoie un email via SMTP.

    Args:
        smtp_host:  Ex: "smtp.gmail.com" ou "smtp.office365.com"
        smtp_port:  Généralement 587 (TLS STARTTLS)
        smtp_user:  Adresse email expéditeur
        smtp_pass:  Mot de passe SMTP (ou mot de passe d'application Google)
        to_email:   Adresse email destinataire
        subject:    Objet de l'email
        body:       Corps du message (texte ou HTML)

    Returns:
        True si succès, False sinon
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"CyberScan Alert <{smtp_user}>"
        msg["To"] = to_email

        # Version texte
        msg.attach(MIMEText(body, "plain", "utf-8"))

        # Version HTML (mise en forme légère)
        html_body = body.replace("\n", "<br>")
        html = f"""
        <html><body style="font-family:Arial,sans-serif;font-size:14px;">
        <div style="background:#1a1a2e;color:#fff;padding:16px;border-radius:8px;">
        <h2 style="color:#f56565;">⚠️ CyberScan — Alerte de Sécurité</h2>
        <div style="background:#2d2d44;padding:12px;border-radius:6px;margin-top:12px;">
        {html_body}
        </div>
        <p style="color:#718096;font-size:12px;margin-top:16px;">
        CyberScan v2.1 — Supervision automatique</p>
        </div></body></html>
        """
        msg.attach(MIMEText(html, "html", "utf-8"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())

        logger.info(f"Email envoyé à {to_email}")
        return True

    except Exception as e:
        logger.error(f"Erreur envoi email : {e}")
        return False


# ─────────────────────────────────────────────
# CANAL 3 : Notification vers le serveur admin
# (la notification Windows est gérée côté admin)
# ─────────────────────────────────────────────
def notify_admin_server(server_ip: str, server_port: int, alert_payload: dict) -> bool:
    """
    Envoie une notification d'alerte au serveur admin via WebSocket.
    Le serveur admin se chargera d'afficher la notification Windows.

    Args:
        server_ip:     IP du serveur admin
        server_port:   Port WebSocket (défaut 8765)
        alert_payload: Dictionnaire avec les données de l'alerte

    Returns:
        True si la connexion et l'envoi ont réussi, False sinon
    """
    import asyncio
    import ssl
    try:
        import websockets

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        async def _send():
            uri = f"wss://{server_ip}:{server_port}"
            async with websockets.connect(uri, ssl=ssl_ctx,
                                          open_timeout=8, close_timeout=5) as ws:
                await ws.send(json.dumps(alert_payload))
                logger.info(f"Alerte envoyée au serveur admin {server_ip}:{server_port}")
                return True

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_send())
        loop.close()
        return result
    except Exception as e:
        logger.error(f"Erreur notification admin : {e}")
        return False


# ─────────────────────────────────────────────
# FONCTION PRINCIPALE : Envoyer une alerte
# sur tous les canaux configurés
# ─────────────────────────────────────────────
def send_alert(alert_type: str, url: str, machine_name: str,
               risk_level: str = "CRITIQUE") -> dict:
    """
    Envoie une alerte de sécurité sur tous les canaux actifs.

    Args:
        alert_type:   Type d'alerte, ex: "Site web dangereux"
        url:          URL ou ressource concernée
        machine_name: Nom de la machine (hostname)
        risk_level:   Niveau de risque (CRITIQUE / ÉLEVÉ / MOYEN)

    Returns:
        dict avec le résultat de chaque canal : {"whatsapp": True, "email": False, ...}
    """
    cfg = _load_alert_config()
    now = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
    hostname = machine_name or socket.gethostname()

    # Construction du message
    message = (
        f"🚨 ALERTE {risk_level} — CyberScan\n"
        f"Machine : {hostname}\n"
        f"Type    : {alert_type}\n"
        f"URL     : {url}\n"
        f"Heure   : {now}\n"
        f"→ Vérifiez le tableau de bord CyberScan."
    )

    results = {}

    # ── WhatsApp (Green API — credentials hardcodés) ──
    wa_cfg = cfg.get('whatsapp', {})
    if wa_cfg.get('enabled') and wa_cfg.get('to_phone'):
        to_phone = wa_cfg['to_phone']
        if not to_phone.endswith('@c.us'):
            to_phone = format_phone_for_green_api(to_phone)
        results['whatsapp'] = send_whatsapp(
            to_phone=to_phone,
            message=message
            # instance_id et api_token = valeurs hardcodées par défaut
        )
    else:
        results['whatsapp'] = None

    # ── Email ─────────────────────────────────
    mail_cfg = cfg.get('email', {})
    if (mail_cfg.get('enabled') and mail_cfg.get('smtp_host')
            and mail_cfg.get('smtp_user') and mail_cfg.get('to_email')):
        subject = f"[CyberScan] 🚨 {risk_level} — {alert_type} sur {hostname}"
        results['email'] = send_email(
            smtp_host=mail_cfg['smtp_host'],
            smtp_port=int(mail_cfg.get('smtp_port', 587)),
            smtp_user=mail_cfg['smtp_user'],
            smtp_pass=mail_cfg.get('smtp_pass', ''),
            to_email=mail_cfg['to_email'],
            subject=subject,
            body=message
        )
    else:
        results['email'] = None  # Non configuré

    # ── Notification admin (Windows côté serveur) ─
    srv_cfg = cfg.get('server', {})
    server_ip = srv_cfg.get('ip') or cfg.get('server_ip', 'localhost')
    server_port = int(srv_cfg.get('port') or cfg.get('server_port', 8765))
    if server_ip and server_ip != 'localhost':
        payload = {
            "action": "security_alert",
            "alert_type": alert_type,
            "url": url,
            "machine": hostname,
            "risk_level": risk_level,
            "timestamp": now,
            "message": message
        }
        results['admin_server'] = notify_admin_server(server_ip, server_port, payload)
    else:
        results['admin_server'] = None

    # Log du résumé
    sent = [k for k, v in results.items() if v is True]
    failed = [k for k, v in results.items() if v is False]
    logger.error(
        f"Alerte '{alert_type}' | Machine: {hostname} | URL: {url}\n"
        f"  Envoyé via : {sent or 'aucun'} | Échec : {failed or 'aucun'}"
    )

    return results


# ─────────────────────────────────────────────
# Test rapide (exécuter directement ce fichier)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) >= 4 and sys.argv[1] == "test_whatsapp":
        # Usage: python alert_sender.py test_whatsapp INSTANCE_ID API_TOKEN PHONE
        # Ex:    python alert_sender.py test_whatsapp 1101234567 abc123token 237690123456
        instance_id = sys.argv[2]
        api_token   = sys.argv[3]
        to_phone    = format_phone_for_green_api(sys.argv[4]) if len(sys.argv) > 4 else "NUMERO@c.us"
        ok = send_whatsapp(
            instance_id=instance_id,
            api_token=api_token,
            to_phone=to_phone,
            message="✅ Test CyberScan — WhatsApp (Green API) configuré avec succès ! Alertes actives."
        )
        print("✅ Message envoyé !" if ok else "❌ Échec envoi WhatsApp")

    elif len(sys.argv) >= 4 and sys.argv[1] == "test_email":
        # Usage: python alert_sender.py test_email user@gmail.com motdepasse dest@mail.com
        ok = send_email(
            smtp_host="smtp.gmail.com", smtp_port=587,
            smtp_user=sys.argv[2], smtp_pass=sys.argv[3],
            to_email=sys.argv[4] if len(sys.argv) > 4 else sys.argv[2],
            subject="[CyberScan] Test alerte email",
            body="✅ Cet email confirme que les alertes CyberScan par email fonctionnent."
        )
        print("✅ Email envoyé !" if ok else "❌ Échec envoi email")
    else:
        print("Usage:")
        print("  python alert_sender.py test_whatsapp INSTANCE_ID API_TOKEN +237690123456")
        print("  python alert_sender.py test_email user@gmail.com mdp dest@mail.com")
        print()
        print("Green API — Setup:")
        print("  1. Créer un compte sur https://green-api.com")
        print("  2. Créer une instance → scanner le QR code avec WhatsApp")
        print("  3. Copier idInstance + apiTokenInstance dans les paramètres CyberScan")

