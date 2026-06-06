"""
CyberScan — Panneau de configuration des alertes (v2.2)
Onglet intégré dans la fenêtre Paramètres (PyQt6)

Canaux disponibles :
  - WhatsApp via Green API (numéro destinataire uniquement — clés hardcodées)
  - Email (SMTP : hôte, port, identifiants, destinataire)
  - Notification Windows (gérée côté admin — aucune config)

Les paramètres sont sauvegardés dans la base SQLite sous la clé "alert_config".
"""

import json
import logging

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QScrollArea, QSizePolicy,
    QSpacerItem, QVBoxLayout, QWidget, QFrame
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
# Thread de test (non-bloquant)
# ══════════════════════════════════════════════════════════════════
class AlertTestThread(QThread):
    result_signal = pyqtSignal(str, bool)   # (canal, succès)

    def __init__(self, channel: str, config: dict, parent=None):
        super().__init__(parent)
        self.channel = channel
        self.config  = config

    def run(self):
        try:
            if self.channel == "whatsapp":
                self._test_whatsapp()
            elif self.channel == "email":
                self._test_email()
        except Exception as e:
            logger.error(f"Erreur test alerte {self.channel}: {e}")
            self.result_signal.emit(self.channel, False)

    # ─────────────────────────────────────────────────────────────
    # Green API — sendMessage
    # Doc: https://green-api.com/en/docs/api/sending/SendMessage/
    # URL : https://{apiUrl}/waInstance{idInstance}/sendMessage/{apiTokenInstance}
    # Body: {"chatId": "<phoneNumber>@c.us", "message": "..."}
    #       chatId = indicatif + numéro SANS le signe +
    # ─────────────────────────────────────────────────────────────
    INSTANCE_ID = "7107642110"
    API_TOKEN   = "20674f06130f4220a1ad168ce623f2eded510d13e482416bac"
    API_URL     = "7107.api.greenapi.com"

    def _format_chat_id(self, raw_phone: str) -> str:
        """Convertit n'importe quel format de numéro en chatId Green API."""
        # Garder uniquement les chiffres
        digits = "".join(c for c in raw_phone if c.isdigit())
        # Supprimer le préfixe 00 si présent
        if digits.startswith("00"):
            digits = digits[2:]
        # chatId format : <digits>@c.us   (sans +, sans espaces)
        return f"{digits}@c.us"

    def _test_whatsapp(self):
        """Envoie un message de test WhatsApp via urllib (stdlib — toujours disponible)."""
        import urllib.request
        import json as _json

        raw_phone = self.config.get("to_phone", "").strip()
        if not raw_phone:
            logger.error("WhatsApp: numéro destinataire vide")
            self.result_signal.emit("whatsapp", False)
            return

        chat_id = self._format_chat_id(raw_phone)
        url = (
            f"https://{self.API_URL}"
            f"/waInstance{self.INSTANCE_ID}"
            f"/sendMessage/{self.API_TOKEN}"
        )
        body = _json.dumps({
            "chatId":  chat_id,
            "message": (
                "✅ *CyberScan — Test réussi !*\n"
                "Les alertes WhatsApp sont actives.\n"
                "Vous recevrez une alerte dès qu'un risque est détecté."
            )
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            import ssl
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                response_text = resp.read().decode("utf-8")
                ok = resp.status == 200 and "idMessage" in response_text
                if not ok:
                    logger.warning(f"WhatsApp HTTP {resp.status}: {response_text[:200]}")
                else:
                    logger.error(f"WhatsApp OK → chatId={chat_id}, réponse={response_text}")
                self.result_signal.emit("whatsapp", ok)
        except Exception as e:
            logger.error(f"Erreur urllib WhatsApp: {e}")
            # Tentative fallback avec requests si disponible
            self._test_whatsapp_requests(chat_id)

    def _test_whatsapp_requests(self, chat_id: str):
        """Fallback via requests si urllib échoue (SSL ou autre)."""
        try:
            import requests
            url = (
                f"https://{self.API_URL}"
                f"/waInstance{self.INSTANCE_ID}"
                f"/sendMessage/{self.API_TOKEN}"
            )
            payload = {
                "chatId":  chat_id,
                "message": "✅ Test CyberScan WhatsApp OK"
            }
            resp = requests.post(url, json=payload,
                                 headers={"Content-Type": "application/json"},
                                 timeout=20, verify=True)
            ok = resp.status_code == 200 and "idMessage" in resp.text
            if not ok:
                logger.warning(f"WhatsApp requests HTTP {resp.status_code}: {resp.text[:200]}")
            self.result_signal.emit("whatsapp", ok)
        except Exception as e:
            logger.error(f"Erreur requests WhatsApp: {e}")
            self.result_signal.emit("whatsapp", False)

    def _test_email(self):
        """Test Email via SMTP."""
        import smtplib
        from email.mime.text import MIMEText
        cfg = self.config
        try:
            msg = MIMEText("Test CyberScan — les alertes email fonctionnent correctement.")
            msg["Subject"] = "[CyberScan] Test alertes"
            msg["From"]    = cfg.get("smtp_user", "")
            msg["To"]      = cfg.get("to_email", "")
            host = cfg.get("smtp_host", "smtp.gmail.com")
            port = int(cfg.get("smtp_port", 587))
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.ehlo()
                s.starttls()
                s.login(cfg.get("smtp_user", ""), cfg.get("smtp_pass", ""))
                s.send_message(msg)
            self.result_signal.emit("email", True)
        except Exception as e:
            logger.error(f"Erreur email SMTP: {e}")
            self.result_signal.emit("email", False)


# ══════════════════════════════════════════════════════════════════
# Palette de couleurs
# ══════════════════════════════════════════════════════════════════
COLORS = {
    "bg_main":      "#0d1117",
    "bg_card":      "#161b22",
    "bg_input":     "#0d1117",
    "border":       "#30363d",
    "border_focus": "#58a6ff",
    "text_primary": "#e6edf3",
    "text_muted":   "#8b949e",
    "text_label":   "#c9d1d9",
    "accent_blue":  "#58a6ff",
    "accent_green": "#3fb950",
    "accent_orange":"#d29922",
    "accent_red":   "#f85149",
    "accent_purple":"#bc8cff",
    "success":      "#3fb950",
    "error":        "#f85149",
    "warning":      "#d29922",
}

CARD_STYLE = f"""
    QGroupBox {{
        background-color: {COLORS['bg_card']};
        border: 1px solid {COLORS['border']};
        border-radius: 10px;
        margin-top: 10px;
        padding: 14px 12px 12px 12px;
        font-size: 14px;
        font-weight: bold;
        color: {COLORS['text_primary']};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 14px;
        padding: 0 6px;
        color: {COLORS['text_primary']};
    }}
"""

INPUT_STYLE = f"""
    QLineEdit {{
        background: {COLORS['bg_input']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        color: {COLORS['text_primary']};
        font-size: 13px;
        padding: 0 10px;
        min-height: 34px;
    }}
    QLineEdit:focus {{
        border-color: {COLORS['border_focus']};
        background: #1c2128;
    }}
    QLineEdit::placeholder {{
        color: {COLORS['text_muted']};
    }}
"""

LABEL_STYLE = f"color: {COLORS['text_label']}; font-size: 13px; min-width: 140px;"

CHECK_STYLE = f"color: {COLORS['text_primary']}; font-size: 13px;"

INFO_BOX_STYLE = (
    f"background: #1c2128; border: 1px solid {COLORS['border']}; "
    f"border-radius: 6px; color: {COLORS['accent_blue']}; "
    f"font-size: 12px; padding: 10px; line-height: 1.5;"
)

TEST_BTN_STYLE = f"""
    QPushButton {{
        background: #21262d;
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        color: {COLORS['accent_blue']};
        font-size: 13px;
        padding: 6px 14px;
        min-height: 32px;
    }}
    QPushButton:hover {{
        background: #30363d;
        border-color: {COLORS['accent_blue']};
        color: white;
    }}
    QPushButton:disabled {{ color: {COLORS['text_muted']}; }}
"""

SAVE_BTN_STYLE = f"""
    QPushButton {{
        background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
            stop:0 #1f6feb, stop:1 #388bfd);
        color: white;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: bold;
        min-height: 42px;
    }}
    QPushButton:hover {{
        background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
            stop:0 #388bfd, stop:1 #58a6ff);
    }}
"""


# ══════════════════════════════════════════════════════════════════
# Widget principal
# ══════════════════════════════════════════════════════════════════
class AlertConfigWidget(QWidget):
    """
    Widget de configuration des alertes.

    Usage dans app.py :
        from alert_config_widget import AlertConfigWidget
        self.alert_widget = AlertConfigWidget(db=self.db)
        tabs.addTab(self.alert_widget, "🔔 Alertes")
    """

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db           = db
        self._test_thread = None
        self.setStyleSheet(f"background-color: {COLORS['bg_main']};")
        self._load_config()
        self._build_ui()

    # ── Config ──────────────────────────────────────────────────
    def _load_config(self):
        self.config = {
            "whatsapp": {"enabled": False, "to_phone": ""},
            "email": {
                "enabled": False,
                "smtp_host": "smtp.gmail.com",
                "smtp_port": 587,
                "smtp_user": "",
                "smtp_pass": "",
                "to_email":  ""
            },
            "windows_notif":    {"enabled": True},
            "watcher_interval": 180
        }
        if self.db:
            try:
                raw = self.db.get_setting("alert_config")
                if raw:
                    saved = json.loads(raw)
                    # Merge récursif
                    for k, v in saved.items():
                        if isinstance(v, dict):
                            self.config.setdefault(k, {}).update(v)
                        else:
                            self.config[k] = v
            except Exception as e:
                logger.error(f"Erreur chargement config alertes: {e}")

    def _save_config(self):
        if self.db:
            try:
                self.db.set_setting("alert_config", json.dumps(self.config))
            except Exception as e:
                logger.error(f"Erreur sauvegarde config alertes: {e}")

    def get_config(self) -> dict:
        return self.config

    # ── UI ──────────────────────────────────────────────────────
    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            f"QScrollArea {{ border: none; background: {COLORS['bg_main']}; }}"
        )

        content = QWidget()
        content.setStyleSheet(f"background-color: {COLORS['bg_main']};")
        layout  = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # En-tête
        title = QLabel("🔔 Configuration des Alertes")
        title.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {COLORS['text_primary']}; "
            f"padding-bottom: 2px;"
        )
        layout.addWidget(title)

        sub = QLabel(
            "Alertes automatiques lors de la détection d'un site dangereux "
            "(vérification toutes les 3 min). Notification Windows = côté administrateur."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        layout.addWidget(sub)

        # Séparateur
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {COLORS['border']}; margin: 2px 0;")
        layout.addWidget(sep)

        layout.addWidget(self._build_whatsapp_group())
        layout.addWidget(self._build_email_group())
        layout.addWidget(self._build_windows_notif_group())

        save_btn = QPushButton("💾  Sauvegarder la configuration")
        save_btn.setStyleSheet(SAVE_BTN_STYLE)
        save_btn.clicked.connect(self._on_save)
        layout.addWidget(save_btn)

        layout.addSpacerItem(
            QSpacerItem(0, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        scroll.setWidget(content)
        main_layout.addWidget(scroll)

    # ── Helpers UI ───────────────────────────────────────────────
    def _card(self, title: str) -> QGroupBox:
        gb = QGroupBox(title)
        gb.setStyleSheet(CARD_STYLE)
        return gb

    def _input(self, placeholder: str = "", password: bool = False) -> QLineEdit:
        le = QLineEdit()
        le.setPlaceholderText(placeholder)
        le.setStyleSheet(INPUT_STYLE)
        if password:
            le.setEchoMode(QLineEdit.EchoMode.Password)
        return le

    def _label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(LABEL_STYLE)
        return lbl

    def _checkbox(self, text: str, checked: bool = False) -> QCheckBox:
        cb = QCheckBox(text)
        cb.setChecked(checked)
        cb.setStyleSheet(CHECK_STYLE)
        return cb

    def _test_btn(self, label: str) -> QPushButton:
        btn = QPushButton(label)
        btn.setStyleSheet(TEST_BTN_STYLE)
        return btn

    def _info_box(self, html: str) -> QLabel:
        lbl = QLabel(html)
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setStyleSheet(INFO_BOX_STYLE)
        return lbl

    # ── Groupe WhatsApp (numéro destinataire uniquement) ─────────
    def _build_whatsapp_group(self) -> QGroupBox:
        wa_cfg = self.config.get("whatsapp", {})
        gb     = self._card("📱  WhatsApp — Green API")
        layout = QVBoxLayout(gb)
        layout.setSpacing(10)

        # Info : clés déjà configurées
        layout.addWidget(self._info_box(
            "✅ <b>Instance Green API configurée</b> (7107642110 — numéro 237690731401)<br>"
            "Entrez uniquement le <b>numéro destinataire</b> qui recevra les alertes."
        ))

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.wa_enabled = self._checkbox(
            "Activer les alertes WhatsApp", wa_cfg.get('enabled', False)
        )
        form.addRow("", self.wa_enabled)

        self.wa_to_phone = self._input("Ex: +237690123456  ou  237690123456")
        self.wa_to_phone.setText(wa_cfg.get('to_phone', ''))
        form.addRow(self._label("Numéro destinataire :"), self.wa_to_phone)

        layout.addLayout(form)

        test_btn = self._test_btn("📤  Envoyer un message WhatsApp de test")
        test_btn.clicked.connect(lambda: self._run_test("whatsapp"))
        layout.addWidget(test_btn)

        self.wa_status = QLabel("")
        self.wa_status.setStyleSheet(f"font-size: 12px; color: {COLORS['text_muted']};")
        layout.addWidget(self.wa_status)

        return gb

    # ── Groupe Email ─────────────────────────────────────────────
    def _build_email_group(self) -> QGroupBox:
        mail_cfg = self.config.get("email", {})
        gb       = self._card("📧  Email — SMTP")
        layout   = QVBoxLayout(gb)
        layout.setSpacing(10)

        layout.addWidget(self._info_box(
            "<b>Gmail</b> : smtp.gmail.com / port 587 — "
            "Utiliser un <i>Mot de passe d'application</i> Google<br>"
            "<b>Outlook</b> : smtp.office365.com / port 587"
        ))

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.mail_enabled = self._checkbox(
            "Activer les alertes Email", mail_cfg.get('enabled', False)
        )
        form.addRow("", self.mail_enabled)

        # Préréglage
        self.mail_preset = QComboBox()
        self.mail_preset.addItems(["Personnalisé", "Gmail", "Outlook / Microsoft 365"])
        self.mail_preset.setStyleSheet(
            f"QComboBox {{ background: {COLORS['bg_input']}; border: 1px solid "
            f"{COLORS['border']}; border-radius: 6px; color: {COLORS['text_primary']}; "
            f"padding: 4px 10px; min-height: 32px; }}"
            f"QComboBox::drop-down {{ border: none; }}"
            f"QComboBox QAbstractItemView {{ background: {COLORS['bg_card']}; "
            f"color: {COLORS['text_primary']}; selection-background-color: #1f6feb; }}"
        )
        self.mail_preset.currentIndexChanged.connect(self._on_preset_changed)
        form.addRow(self._label("Préréglage :"), self.mail_preset)

        self.mail_host = self._input("smtp.gmail.com")
        self.mail_host.setText(mail_cfg.get('smtp_host', 'smtp.gmail.com'))
        form.addRow(self._label("Serveur SMTP :"), self.mail_host)

        self.mail_port = self._input("587")
        self.mail_port.setText(str(mail_cfg.get('smtp_port', 587)))
        form.addRow(self._label("Port :"), self.mail_port)

        self.mail_user = self._input("votre-email@gmail.com")
        self.mail_user.setText(mail_cfg.get('smtp_user', ''))
        form.addRow(self._label("Email expéditeur :"), self.mail_user)

        self.mail_pass = self._input("Mot de passe ou clé d'application", password=True)
        self.mail_pass.setText(mail_cfg.get('smtp_pass', ''))
        form.addRow(self._label("Mot de passe :"), self.mail_pass)

        self.mail_to = self._input("admin@entreprise.com")
        self.mail_to.setText(mail_cfg.get('to_email', ''))
        form.addRow(self._label("Email destinataire :"), self.mail_to)

        layout.addLayout(form)

        test_btn = self._test_btn("📤  Envoyer un email de test")
        test_btn.clicked.connect(lambda: self._run_test("email"))
        layout.addWidget(test_btn)

        self.mail_status = QLabel("")
        self.mail_status.setStyleSheet(f"font-size: 12px; color: {COLORS['text_muted']};")
        layout.addWidget(self.mail_status)

        return gb

    def _on_preset_changed(self, index: int):
        presets = {
            1: ("smtp.gmail.com",      "587"),
            2: ("smtp.office365.com",  "587"),
        }
        if index in presets:
            self.mail_host.setText(presets[index][0])
            self.mail_port.setText(presets[index][1])

    # ── Groupe Notification Windows ──────────────────────────────
    def _build_windows_notif_group(self) -> QGroupBox:
        win_cfg = self.config.get("windows_notif", {})
        gb      = self._card("🖥️  Notification Windows — Bureau admin")
        layout  = QVBoxLayout(gb)
        layout.setSpacing(10)

        layout.addWidget(self._info_box(
            "Les alertes de sécurité s'affichent en <b>popup sur le bureau</b> "
            "de l'administrateur (machine où tourne CyberScan Admin).<br>"
            "<b>Aucune configuration requise.</b>"
        ))

        self.win_enabled = self._checkbox(
            "Afficher les notifications Windows sur le bureau admin",
            win_cfg.get('enabled', True)
        )
        layout.addWidget(self.win_enabled)

        return gb

    # ── Collecte + Sauvegarde ────────────────────────────────────
    def _collect_config(self):
        """Lit les champs et met à jour self.config."""
        self.config["whatsapp"] = {
            "enabled":  self.wa_enabled.isChecked(),
            "to_phone": self.wa_to_phone.text().strip()
        }
        self.config["email"] = {
            "enabled":   self.mail_enabled.isChecked(),
            "smtp_host": self.mail_host.text().strip(),
            "smtp_port": int(self.mail_port.text().strip() or "587"),
            "smtp_user": self.mail_user.text().strip(),
            "smtp_pass": self.mail_pass.text(),
            "to_email":  self.mail_to.text().strip()
        }
        self.config["windows_notif"] = {
            "enabled": self.win_enabled.isChecked()
        }

    def _on_save(self):
        self._collect_config()
        self._save_config()
        # ─ Diffuser la nouvelle config à tous les agents connectés ─────────
        try:
            import server as server_module
            import asyncio
            try:
                import sys
                app_module = sys.modules.get('__main__')
                loop = getattr(app_module, 'server_loop', None)
            except Exception:
                loop = None
            if loop and server_module.connected_agents:
                asyncio.run_coroutine_threadsafe(
                    server_module.broadcast_config(self.config), loop
                )
                logger.info("Config alertes diffusée aux agents connectés")
        except Exception as e:
            logger.error(f"Erreur diffusion config: {e}")
        QMessageBox.information(
            self, "Sauvegardé",
            "✅ Configuration des alertes sauvegardée.\n\n"
            "Les agents connectés ont reçu la nouvelle configuration automatiquement."
        )

    def _run_test(self, channel: str):
        self._collect_config()
        status_lbl = self.wa_status if channel == "whatsapp" else self.mail_status
        status_lbl.setText("⏳ Envoi en cours...")
        status_lbl.setStyleSheet(
            f"font-size: 12px; color: {COLORS['accent_orange']}; font-weight: bold;"
        )
        cfg = self.config.get(channel, {})
        self._test_thread = AlertTestThread(channel=channel, config=cfg, parent=self)
        self._test_thread.result_signal.connect(self._on_test_result)
        self._test_thread.start()

    def _on_test_result(self, channel: str, ok: bool):
        lbl = self.wa_status if channel == "whatsapp" else self.mail_status
        if ok:
            lbl.setText("✅ Message envoyé avec succès !")
            lbl.setStyleSheet(
                f"font-size: 12px; color: {COLORS['success']}; font-weight: bold;"
            )
        else:
            lbl.setText("❌ Échec — vérifiez le numéro ou la connexion réseau")
            lbl.setStyleSheet(
                f"font-size: 12px; color: {COLORS['error']}; font-weight: bold;"
            )
