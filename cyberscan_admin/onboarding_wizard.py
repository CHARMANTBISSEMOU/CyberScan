"""
CyberScan - Wizard de premier lancement
Guide l'utilisateur pas-à-pas pour une configuration initiale simplifiée
"""

from PyQt6.QtWidgets import (
    QWizard, QWizardPage, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QComboBox, QCheckBox, QTextEdit,
    QProgressBar, QMessageBox, QFrame, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap
import webbrowser
import logging

class APIKeyValidator(QThread):
    """Valide les clés API en arrière-plan."""
    validation_complete = pyqtSignal(str, bool, str)  # provider, success, message
    
    def __init__(self, groq_key, claude_key):
        super().__init__()
        self.groq_key = groq_key
        self.claude_key = claude_key
    
    def run(self):
        # Validation Groq
        if self.groq_key:
            try:
                from groq import Groq
                client = Groq(api_key=self.groq_key)
                # Test simple
                response = client.chat.completions.create(
                    model="llama-3.1-8b-instant",
                    messages=[{"role": "user", "content": "Test"}],
                    max_tokens=5
                )
                self.validation_complete.emit("groq", True, "✅ Clé Groq valide")
            except Exception as e:
                self.validation_complete.emit("groq", False, f"❌ Erreur Groq: {str(e)[:50]}")
        
        # Validation Claude (optionnelle)
        if self.claude_key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=self.claude_key)
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=5,
                    messages=[{"role": "user", "content": "Test"}]
                )
                self.validation_complete.emit("claude", True, "✅ Clé Claude valide")
            except Exception as e:
                self.validation_complete.emit("claude", False, f"❌ Erreur Claude: {str(e)[:50]}")


class WelcomePage(QWizardPage):
    """Page 1: Bienvenue et choix du mode."""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Bienvenue dans CyberScan")
        self.setSubTitle("Votre assistant de cybersécurité simplifié")
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Logo/Icon
        icon_label = QLabel("🛡️")
        icon_label.setFont(QFont("Segoe UI", 72))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Description
        desc = QLabel(
            "CyberScan analyse la sécurité de vos machines Windows et génère des rapports détaillés.\n\n"
            "Choisissez votre niveau d'expérience :"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("font-size: 14px; color: #4a5568;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        # Choix du mode
        self.mode_group = QButtonGroup(self)
        
        self.simple_radio = QRadioButton("🟢 Mode Simple (Recommandé)")
        self.simple_radio.setChecked(True)
        self.simple_radio.setStyleSheet("""
            QRadioButton { font-size: 16px; font-weight: bold; padding: 10px; }
            QRadioButton::checked { color: #38a169; }
        """)
        
        simple_desc = QLabel("Interface simplifiée avec les actions essentielles seulement.\n"
                           "Idéal pour débuter rapidement.")
        simple_desc.setStyleSheet("color: #718096; margin-left: 30px;")
        simple_desc.setIndent(30)
        
        self.expert_radio = QRadioButton("🔵 Mode Expert")
        self.expert_radio.setStyleSheet("""
            QRadioButton { font-size: 16px; font-weight: bold; padding: 10px; }
            QRadioButton::checked { color: #3182ce; }
        """)
        
        expert_desc = QLabel("Accès à toutes les fonctionnalités avancées:\n"
                           "Configuration détaillée, analyse réseau, logs techniques...")
        expert_desc.setStyleSheet("color: #718096; margin-left: 30px;")
        expert_desc.setIndent(30)
        
        self.mode_group.addButton(self.simple_radio)
        self.mode_group.addButton(self.expert_radio)
        
        layout.addWidget(self.simple_radio)
        layout.addWidget(simple_desc)
        layout.addWidget(self.expert_radio)
        layout.addWidget(expert_desc)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def get_selected_mode(self):
        return "simple" if self.simple_radio.isChecked() else "expert"


class APISetupPage(QWizardPage):
    """Page 2: Configuration des clés API guidée."""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Configuration des clés API")
        self.setSubTitle("L'analyse IA nécessite une clé API (gratuite)")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Explication
        help_text = QLabel(
            "🔑 <b>Pourquoi une clé API?</b><br>"
            "CyberScan utilise l'IA (Groq/Claude) pour analyser les données de sécurité et générer des scores.\n<br><br>"
            "✅ <b>Obtenir une clé gratuite en 2 minutes:</b>"
        )
        help_text.setWordWrap(True)
        help_text.setStyleSheet("font-size: 13px; background: #ebf8ff; padding: 15px; border-radius: 8px;")
        layout.addWidget(help_text)
        
        # Section Groq - ZONE AGRANDIE avec meilleur layout
        groq_frame = QFrame()
        groq_frame.setMinimumHeight(180)
        groq_frame.setStyleSheet("""
            QFrame {
                background: #ebf8ff; 
                border: 2px solid #3182ce; 
                border-radius: 12px; 
                padding: 15px;
                margin: 5px 0;
            }
            QLabel { color: #2c5282; }
        """)
        groq_layout = QVBoxLayout(groq_frame)
        groq_layout.setSpacing(10)
        groq_layout.setContentsMargins(15, 15, 15, 15)
        
        # Titre avec lien direct
        groq_title_layout = QHBoxLayout()
        groq_title = QLabel("🚀 Étape 1: Créer une clé API Groq (Gratuit)")
        groq_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #2c5282;")
        groq_title_layout.addWidget(groq_title)
        groq_title_layout.addStretch()
        
        # Lien direct cliquable
        groq_link = QLabel("<a href='https://console.groq.com/keys' style='color: #3182ce;'>🔗 Ouvrir console.groq.com</a>")
        groq_link.setOpenExternalLinks(True)
        groq_link.setStyleSheet("font-size: 12px; color: #3182ce;")
        groq_title_layout.addWidget(groq_link)
        groq_layout.addLayout(groq_title_layout)
        
        # Instructions étape par étape
        groq_steps = QLabel(
            "<b>Instructions:</b><br>"
            "1️⃣ Cliquez sur le lien ci-dessus pour ouvrir Groq<br>"
            "2️⃣ Créez un compte gratuit (email + mot de passe)<br>"
            "3️⃣ Allez dans 'API Keys' puis 'Create API Key'<br>"
            "4️⃣ Copiez la clé qui commence par 'gsk_' dans le champ ci-dessous"
        )
        groq_steps.setStyleSheet("color: #2c5282; font-size: 13px; line-height: 1.5;")
        groq_steps.setWordWrap(True)
        groq_layout.addWidget(groq_steps)
        
        # Champ de saisie avec bouton d'aide
        groq_input_layout = QHBoxLayout()
        self.groq_key_input = QLineEdit()
        self.groq_key_input.setPlaceholderText("Collez votre clé API Groq ici (gsk_xxxxxxxxxxxx...)")
        self.groq_key_input.setStyleSheet("""
            padding: 10px; 
            font-family: monospace; 
            font-size: 13px;
            border: 2px solid #3182ce;
            border-radius: 6px;
            background: white;
        """)
        self.groq_key_input.setMinimumHeight(35)
        
        groq_input_layout.addWidget(self.groq_key_input, stretch=1)
        groq_layout.addLayout(groq_input_layout)
        
        # Indicateur validation
        self.groq_status = QLabel("⏳ En attente de la clé... (format: gsk_xxxxxxxxxxxx)")
        self.groq_status.setStyleSheet("color: #2c5282; font-style: italic; font-size: 12px; padding: 5px;")
        groq_layout.addWidget(self.groq_status)
        
        # Initialiser flags de validation
        self.groq_valid = False
        self.claude_valid = False
        
        layout.addWidget(groq_frame)
        
        # Section Claude (optionnel)
        claude_check = QCheckBox("J'ai aussi une clé Claude (optionnel, recommandé pour meilleure précision)")
        claude_check.setStyleSheet("margin-top: 10px;")
        claude_check.stateChanged.connect(self.toggle_claude)
        layout.addWidget(claude_check)
        
        self.claude_frame = QFrame()
        self.claude_frame.setStyleSheet("""
            QFrame {
                background: #fffbeb; 
                border: 2px solid #d69e2e; 
                border-radius: 8px; 
                padding: 10px;
            }
            QLabel { color: #744210; }
        """)
        self.claude_frame.setVisible(False)
        claude_layout = QVBoxLayout(self.claude_frame)
        
        claude_title = QLabel("🤖 Étape 2 (Optionnel): Clé Claude")
        claude_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #744210;")
        claude_layout.addWidget(claude_title)
        
        self.open_claude_btn = QPushButton("🌐 Ouvrir console.anthropic.com")
        self.open_claude_btn.setStyleSheet("background: #d69e2e; color: white; padding: 8px 16px;")
        self.open_claude_btn.clicked.connect(lambda: webbrowser.open("https://console.anthropic.com/settings/keys"))
        
        self.claude_key_input = QLineEdit()
        self.claude_key_input.setPlaceholderText("Collez votre clé API Claude ici (sk-ant-...)")
        self.claude_key_input.setStyleSheet("padding: 8px; font-family: monospace;")
        
        claude_input_layout = QHBoxLayout()
        claude_input_layout.addWidget(self.open_claude_btn)
        claude_input_layout.addWidget(self.claude_key_input, stretch=1)
        claude_layout.addLayout(claude_input_layout)
        
        self.claude_status = QLabel("⏳ Optionnel")
        self.claude_status.setStyleSheet("color: #744210; font-style: italic;")
        claude_layout.addWidget(self.claude_status)
        
        layout.addWidget(self.claude_frame)
        
        # Bouton tester
        self.test_btn = QPushButton("✅ Tester les clés API")
        self.test_btn.setStyleSheet("background: #38a169; color: white; font-weight: bold; padding: 12px;")
        self.test_btn.clicked.connect(self.test_keys)
        layout.addWidget(self.test_btn)
        
        # Note
        note = QLabel("💡 Vous pourrez modifier ces clés plus tard dans Paramètres > Clés API")
        note.setStyleSheet("color: #718096; font-style: italic;")
        layout.addWidget(note)
        layout.addStretch()
        
        self.setLayout(layout)
        self.validator = None
    
    def toggle_claude(self, state):
        self.claude_frame.setVisible(state == Qt.CheckState.Checked.value)
    
    def test_keys(self):
        groq_key = self.groq_key_input.text().strip()
        claude_key = self.claude_key_input.text().strip() if self.claude_frame.isVisible() else ""
        
        if not groq_key and not claude_key:
            QMessageBox.warning(self, "Clés manquantes", 
                "Veuillez entrer au moins une clé API (Groq ou Claude).")
            return
        
        self.test_btn.setEnabled(False)
        self.test_btn.setText("🔄 Test en cours...")
        self.groq_status.setText("🔄 Validation en cours...")
        
        self.validator = APIKeyValidator(groq_key, claude_key)
        self.validator.validation_complete.connect(self.on_validation)
        self.validator.start()
    
    def on_validation(self, provider, success, message):
        if provider == "groq":
            self.groq_status.setText(message)
            self.groq_status.setStyleSheet("color: #38a169; font-weight: bold;" if success else "color: #c53030;")
            self.groq_valid = success
        elif provider == "claude":
            self.claude_status.setText(message)
            self.claude_status.setStyleSheet("color: #38a169; font-weight: bold;" if success else "color: #c53030;")
            self.claude_valid = success
        
        # Réactiver le bouton
        self.test_btn.setEnabled(True)
        self.test_btn.setText("✅ Tester les clés API")
        
        # Forcer la mise à jour du bouton Next du wizard
        self.completeChanged.emit()
    
    def get_api_keys(self):
        return {
            "groq": self.groq_key_input.text().strip(),
            "claude": self.claude_key_input.text().strip() if self.claude_frame.isVisible() else ""
        }
    
    def isComplete(self):
        # Au moins une clé Groq avec format valide pour continuer (gsk_...)
        groq_key = self.groq_key_input.text().strip()
        return len(groq_key) > 20 and groq_key.startswith("gsk_")


class SummaryPage(QWizardPage):
    """Page 3: Résumé et finalisation."""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Configuration terminée !")
        self.setSubTitle("Vous êtes prêt à sécuriser votre réseau")
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Succès
        success_icon = QLabel("🎉")
        success_icon.setFont(QFont("Segoe UI", 64))
        success_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_icon)
        
        # Message
        msg = QLabel(
            "<b>Félicitations !</b><br><br>"
            "CyberScan est maintenant configuré et prêt à l'emploi.<br><br>"
            "<b>Prochaines étapes :</b>"
        )
        msg.setWordWrap(True)
        msg.setStyleSheet("font-size: 15px; text-align: center;")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(msg)
        
        # Liste actions
        actions = QLabel(
            "1️⃣ Déployez l'agent CyberScan sur vos machines Windows\n"
            "2️⃣ Les machines apparaîtront automatiquement dans la liste\n"
            "3️⃣ Lancez un 'Scan Rapide' pour commencer\n"
            "4️⃣ Consultez les rapports de sécurité générés automatiquement"
        )
        actions.setStyleSheet("""
            background: #f0fff4; 
            border: 2px solid #38a169; 
            border-radius: 10px; 
            padding: 20px;
            font-size: 14px;
            line-height: 1.8;
        """)
        layout.addWidget(actions)
        
        # Astuce
        tip = QLabel(
            "💡 <b>Astuce :</b> Le mode 'Simple' affiche uniquement les actions essentielles.\n"
            "Vous pouvez passer en mode 'Expert' dans Paramètres à tout moment."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #2c5282; background: #ebf8ff; padding: 15px; border-radius: 8px;")
        layout.addWidget(tip)
        
        layout.addStretch()
        self.setLayout(layout)


class OnboardingWizard(QWizard):
    """Wizard complet de premier lancement."""
    
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        
        self.setWindowTitle("Configuration initiale - CyberScan")
        self.setFixedSize(700, 600)
        
        # Pages
        self.welcome_page = WelcomePage()
        self.api_page = APISetupPage()
        self.summary_page = SummaryPage()
        
        self.addPage(self.welcome_page)
        self.addPage(self.api_page)
        self.addPage(self.summary_page)
        
        # Style
        self.setStyleSheet("""
            QWizard {
                background: #f7fafc;
            }
            QWizardPage {
                background: white;
            }
            QPushButton {
                border-radius: 6px;
                font-weight: bold;
            }
            QLineEdit {
                border: 2px solid #e2e8f0;
                border-radius: 6px;
                padding: 8px;
            }
            QLineEdit:focus {
                border-color: #3182ce;
            }
        """)
        
        self.button(QWizard.WizardButton.FinishButton).clicked.connect(self.save_config)
    
    def save_config(self):
        """Sauvegarde la configuration."""
        try:
            # Sauvegarder le mode
            mode = self.welcome_page.get_selected_mode()
            self.db.set_api_key("interface_mode", mode)
            
            # Sauvegarder les clés API
            keys = self.api_page.get_api_keys()
            if keys["groq"]:
                self.db.set_api_key("groq", keys["groq"])
            if keys["claude"]:
                self.db.set_api_key("claude", keys["claude"])
            
            # Marquer le wizard comme terminé
            self.db.set_api_key("onboarding_complete", "true")
            
            logging.info(f"Configuration initiale terminée - Mode: {mode}")
            
        except Exception as e:
            logging.error(f"Erreur sauvegarde config wizard: {e}")
    
    def get_selected_mode(self):
        return self.welcome_page.get_selected_mode()


def should_show_wizard(db):
    """Détermine si le wizard doit être affiché."""
    try:
        # Si jamais exécuté ou pas de clé API Groq
        onboarding_done = db.get_api_key("onboarding_complete")
        groq_key = db.get_api_key("groq")
        
        return (not onboarding_done) or (not groq_key)
    except:
        return True


if __name__ == "__main__":
    import sys
    from PyQt6.QtWidgets import QApplication
    from database import CyberScanDB
    
    app = QApplication(sys.argv)
    
    db = CyberScanDB("test_wizard.db")
    wizard = OnboardingWizard(db)
    wizard.show()
    
    sys.exit(app.exec())
