"""
CyberScan - Dashboard de synthèse en une page
Vue d'ensemble immédiate pour le mode Simple
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QFrame, QProgressBar, QGridLayout, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush


class DashboardCard(QFrame):
    """Carte d'information stylisée pour le dashboard."""
    
    def __init__(self, title, value, subtitle="", color="#3182ce", parent=None):
        super().__init__(parent)
        self.color = color
        self.value_lbl = None
        
        self.setStyleSheet(f"""
            QFrame {{
                background: white;
                border: 2px solid {color};
                border-radius: 12px;
                padding: 15px;
            }}
        """)
        
        # Taille fixe pour éviter la superposition
        self.setMinimumWidth(200)
        self.setMinimumHeight(130)
        self.setMaximumWidth(300)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Titre
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
        layout.addWidget(title_lbl)
        
        # Valeur principale
        self.value_lbl = QLabel(str(value))
        self.value_lbl.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: bold;")
        self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.value_lbl)
        
        # Sous-titre
        if subtitle:
            sub_lbl = QLabel(subtitle)
            sub_lbl.setStyleSheet("color: #718096; font-size: 11px;")
            sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub_lbl.setWordWrap(True)
            layout.addWidget(sub_lbl)
        
        self.setLayout(layout)
    
    def setValue(self, value):
        """Met à jour la valeur affichée."""
        if self.value_lbl:
            self.value_lbl.setText(str(value))


class RiskItem(QFrame):
    """Élément de risque affiché dans le dashboard."""
    
    def __init__(self, severity, title, machine, parent=None):
        super().__init__(parent)
        
        colors = {
            "critique": ("#c53030", "🔴"),
            "élevé": ("#dd6b20", "🟠"),
            "moyen": ("#d69e2e", "🟡"),
            "faible": ("#38a169", "🟢")
        }
        
        color, icon = colors.get(severity.lower(), ("#718096", "⚪"))
        
        self.setStyleSheet(f"""
            QFrame {{
                background: white;
                border-left: 4px solid {color};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Icône de sévérité
        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI", 16))
        layout.addWidget(icon_lbl)
        
        # Description
        desc_layout = QVBoxLayout()
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 13px; font-weight: bold; color: #2d3748;")
        desc_layout.addWidget(title_lbl)
        
        machine_lbl = QLabel(f"💻 {machine}")
        machine_lbl.setStyleSheet("font-size: 11px; color: #718096;")
        desc_layout.addWidget(machine_lbl)
        
        layout.addLayout(desc_layout, stretch=1)
        
        # Badge sévérité
        badge = QLabel(severity.upper())
        badge.setStyleSheet(f"""
            background: {color}22;
            color: {color};
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
        """)
        layout.addWidget(badge)
        
        self.setLayout(layout)


class DashboardTab(QWidget):
    """Onglet Dashboard avec synthèse en une page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_main = parent
        self.setup_ui()
        
        # Rafraîchissement automatique
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.update_dashboard)
        self.refresh_timer.start(5000)  # Toutes les 5 secondes
    
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Titre
        title = QLabel("📊 Vue d'ensemble de votre sécurité")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2d3748;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Sous-titre explicatif
        subtitle = QLabel(
            "Cette page résume l'état de sécurité de toutes vos machines. "
            "Elle se met à jour automatiquement."
        )
        subtitle.setStyleSheet("color: #718096; font-size: 12px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        
        # === CARTES DE SYNTHÈSE ===
        # Utiliser un QGridLayout pour éviter la superposition sur petits écrans
        cards_widget = QWidget()
        cards_layout = QGridLayout(cards_widget)
        cards_layout.setSpacing(15)
        cards_layout.setContentsMargins(10, 10, 10, 10)
        
        self.card_total = DashboardCard("🖥️ Machines Total", "—", "dans le système", "#3182ce")
        self.card_online = DashboardCard("✅ En Ligne", "—", "prêtes pour analyse", "#38a169")
        self.card_offline = DashboardCard("⚫ Hors Ligne", "—", "à vérifier", "#718096")
        self.card_score = DashboardCard("📊 Score Moyen", "—", "sur 100 points", "#805ad5")
        
        # Disposition en grille 2x2 pour éviter superposition
        cards_layout.addWidget(self.card_total, 0, 0)
        cards_layout.addWidget(self.card_online, 0, 1)
        cards_layout.addWidget(self.card_offline, 1, 0)
        cards_layout.addWidget(self.card_score, 1, 1)
        
        # Container avec scroll si nécessaire
        cards_scroll = QScrollArea()
        cards_scroll.setWidgetResizable(True)
        cards_scroll.setWidget(cards_widget)
        cards_scroll.setMaximumHeight(320)
        cards_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        layout.addWidget(cards_scroll)
        
        # === ACTIONS RAPIDES ===
        actions_frame = QFrame()
        actions_frame.setStyleSheet("background: #ebf8ff; border-radius: 10px; padding: 15px;")
        actions_layout = QHBoxLayout(actions_frame)
        
        actions_title = QLabel("⚡ Actions Rapides:")
        actions_title.setStyleSheet("font-weight: bold; color: #2c5282;")
        actions_layout.addWidget(actions_title)
        
        # Bouton scan rapide tout
        self.scan_all_btn = QPushButton("🔍 Analyser toutes les machines (Rapide)")
        self.scan_all_btn.setStyleSheet("""
            QPushButton {
                background: #38a169;
                color: white;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 8px;
            }
            QPushButton:hover { background: #2f855a; }
        """)
        self.scan_all_btn.clicked.connect(self.scan_all_quick)
        self.scan_all_btn.setToolTip("Lance une analyse rapide (~20s) sur toutes les machines connectées")
        actions_layout.addWidget(self.scan_all_btn)
        
        # Bouton rapport global
        self.report_btn = QPushButton("📄 Rapport Global")
        self.report_btn.setStyleSheet("""
            QPushButton {
                background: #3182ce;
                color: white;
                padding: 10px 20px;
                border-radius: 8px;
            }
            QPushButton:hover { background: #2c5282; }
        """)
        self.report_btn.clicked.connect(self.generate_global_report)
        self.report_btn.setToolTip("Génère un rapport PDF consolidé de tout le parc")
        actions_layout.addWidget(self.report_btn)
        
        actions_layout.addStretch()
        layout.addWidget(actions_frame)
        
        # === SECTION RISQUES ===
        risks_frame = QFrame()
        risks_frame.setStyleSheet("background: white; border-radius: 10px; padding: 15px;")
        risks_layout = QVBoxLayout(risks_frame)
        
        risks_header = QLabel("⚠️ Points d'attention prioritaires")
        risks_header.setStyleSheet("font-size: 14px; font-weight: bold; color: #c53030;")
        risks_layout.addWidget(risks_header)
        
        self.risks_container = QVBoxLayout()
        self.risks_container.setSpacing(8)
        
        # Message par défaut
        self.no_risks_label = QLabel("✅ Aucun risque critique détecté. Votre parc est en bonne santé!")
        self.no_risks_label.setStyleSheet("color: #38a169; font-size: 13px; padding: 20px; background: #f0fff4; border-radius: 8px;")
        self.no_risks_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risks_container.addWidget(self.no_risks_label)
        
        risks_layout.addLayout(self.risks_container)
        
        # Scroll area pour les risques
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(risks_frame)
        scroll.setMinimumHeight(200)
        layout.addWidget(scroll)
        
        # === CONSEIL DU JOUR ===
        tip_frame = QFrame()
        tip_frame.setStyleSheet("background: #fffaf0; border-left: 4px solid #d69e2e; padding: 12px;")
        tip_layout = QHBoxLayout(tip_frame)
        
        tip_icon = QLabel("💡")
        tip_icon.setFont(QFont("Segoe UI", 20))
        tip_layout.addWidget(tip_icon)
        
        self.tip_label = QLabel(
            "Conseil: Lancez des analyses régulières (quotidiennes recommandées) "
            "pour détecter rapidement les nouvelles menaces."
        )
        self.tip_label.setStyleSheet("color: #744210; font-size: 12px;")
        self.tip_label.setWordWrap(True)
        tip_layout.addWidget(self.tip_label, stretch=1)
        
        layout.addWidget(tip_frame)
        
        layout.addStretch()
        self.setLayout(layout)
        
        # Chargement initial
        self.update_dashboard()
    
    def update_dashboard(self):
        """Met à jour toutes les métriques du dashboard."""
        try:
            if not self.parent_main or not hasattr(self.parent_main, 'db'):
                return
            
            db = self.parent_main.db
            machines = db.get_all_machines()
            
            if not machines:
                self.card_total.update_value("0")
                self.card_online.update_value("0")
                self.card_offline.update_value("0")
                self.card_score.update_value("—")
                return
            
            # Compter les machines
            total = len(machines)
            online = sum(1 for m in machines if m.get('status') == 'online')
            offline = total - online
            
            # Calculer le score moyen
            scores = [m.get('last_score') for m in machines if m.get('last_score') is not None]
            avg_score = int(sum(scores) / len(scores)) if scores else None
            
            # Mettre à jour les cartes
            self.card_total.setValue(total)
            self.card_online.setValue(online)
            self.card_offline.setValue(offline)
            
            if avg_score is not None:
                self.card_score.setValue(avg_score)
                score_color = self.get_score_color(avg_score)
                self.card_score.setStyleSheet(f"""
                    QFrame {{
                        background: white;
                        border: 2px solid {score_color};
                        border-radius: 12px;
                        padding: 15px;
                        min-width: 180px;
                        min-height: 120px;
                    }}
                """)
            else:
                self.card_score.setValue("—")
            
            # Identifier les risques (machines avec score faible)
            self.update_risks_list(machines)
            
        except Exception as e:
            print(f"Erreur mise à jour dashboard: {e}")
    
    def get_score_color(self, score):
        """Retourne la couleur associée au score."""
        if score >= 80:
            return "#38a169"
        elif score >= 60:
            return "#d69e2e"
        elif score >= 40:
            return "#dd6b20"
        else:
            return "#c53030"
    
    def update_risks_list(self, machines):
        """Met à jour la liste des risques prioritaires."""
        # Nettoyer les risques existants
        while self.risks_container.count():
            item = self.risks_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Identifier les machines à risque
        risky_machines = [
            m for m in machines 
            if m.get('last_score') is not None and m.get('last_score', 100) < 60
        ]
        
        # Trier par score croissant (les plus mauvais d'abord)
        risky_machines.sort(key=lambda x: x.get('last_score', 100))
        
        if not risky_machines:
            # Réafficher le message positif
            self.no_risks_label = QLabel("✅ Aucun risque critique détecté. Votre parc est en bonne santé!")
            self.no_risks_label.setStyleSheet("color: #38a169; font-size: 13px; padding: 20px;")
            self.no_risks_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.risks_container.addWidget(self.no_risks_label)
        else:
            # Afficher les top 5 risques
            for machine in risky_machines[:5]:
                score = machine.get('last_score', 0)
                hostname = machine.get('hostname', 'Inconnu')
                
                if score < 30:
                    severity = "critique"
                    title = "Sécurité très compromise"
                elif score < 50:
                    severity = "élevé"
                    title = "Risques importants détectés"
                else:
                    severity = "moyen"
                    title = "Points à améliorer"
                
                risk_item = RiskItem(severity, title, hostname)
                self.risks_container.addWidget(risk_item)
    
    def scan_all_quick(self):
        """Lance un scan rapide sur toutes les machines."""
        if self.parent_main and hasattr(self.parent_main, 'scan_all_machines'):
            self.parent_main.scan_all_machines(mode='quick')
    
    def generate_global_report(self):
        """Génère un rapport global du parc."""
        QMessageBox.information(
            self,
            "Rapport Global",
            "Fonctionnalité de rapport global en cours de développement.\n\n"
            "Pour l'instant, vous pouvez exporter les rapports individuels "
            "depuis l'onglet Machines."
        )


if __name__ == "__main__":
    import sys
    from PyQt6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    dashboard = DashboardTab()
    dashboard.setWindowTitle("CyberScan Dashboard")
    dashboard.resize(900, 700)
    dashboard.show()
    
    sys.exit(app.exec())
