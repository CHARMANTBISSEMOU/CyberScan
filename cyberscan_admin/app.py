import sys
import os
import asyncio
import threading
import json
import ctypes
import socket
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QLabel,
                             QPushButton, QHBoxLayout, QDialog, QFormLayout, QLineEdit, 
                             QMessageBox, QComboBox, QGroupBox, QGridLayout, QProgressBar,
                             QTextEdit, QDialogButtonBox, QTimeEdit, QCheckBox, QInputDialog,
                             QTabWidget, QSplitter, QFrame, QScrollArea, QMenu)
from PyQt6.QtCore import QTimer, Qt, QTime, pyqtSlot, Q_ARG, QMetaObject
from PyQt6.QtGui import QColor, QFont, QBrush
from database import CyberScanDB
from network_scanner_fixed import NetworkScannerFixed
from traffic_monitor_simple import TrafficMonitorSimple
from onboarding_wizard import OnboardingWizard, should_show_wizard
from dashboard_tab import DashboardTab
import server
import logging
import ia_analyzer

# Démarre le serveur WebSocket dans un thread séparé avec sa propre boucle asyncio
server_loop = None
# Machines en cours de scan (set d'agent_id)
scanning_machines = set()
scan_progress_total = 0
scan_progress_done = 0
scan_step_total = 0
scan_step_done = 0
scan_step_label = ""
last_ai_error = None
# Compteur pour l'animation de scan (clignotement)
scan_anim_tick = 0

def run_server():
    global server_loop
    try:
        logging.info("Démarrage du serveur WebSocket CyberScan sur le port 8765...")
        server_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(server_loop)
        server_loop.run_until_complete(server.main())
    except Exception as e:
        logging.exception(f"Erreur démarrage serveur WebSocket CyberScan sur le port 8765: {e}")

# ============================================================
# Utilitaires Score
# ============================================================
def score_color(score):
    if score is None: return "#888888"
    if score <= 20: return "#c53030"
    if score <= 40: return "#dd6b20"
    if score <= 60: return "#d69e2e"
    if score <= 80: return "#38a169"
    return "#276749"

def score_label(score):
    if score is None: return "N/A"
    if score <= 20: return "CRITIQUE"
    if score <= 40: return "ÉLEVÉ"
    if score <= 60: return "MOYEN"
    if score <= 80: return "BON"
    return "EXCELLENT"

def score_description(score):
    if score is None: return "Aucun scan effectué"

# ============================================================
# Alertes Desktop
# ============================================================
def show_desktop_notification(title, message, icon_type="info"):
    """Affiche une notification desktop native Windows."""
    try:
        import win32api
        import win32con
        import win32gui
        
        # Icones Windows
        icons = {
            "info": win32con.MB_ICONINFORMATION,
            "warning": win32con.MB_ICONWARNING,
            "error": win32con.MB_ICONERROR,
            "question": win32con.MB_ICONQUESTION
        }
        
        icon = icons.get(icon_type, win32con.MB_ICONINFORMATION)
        
        # Afficher la notification
        win32api.MessageBox(0, message, title, icon)
        
    except ImportError:
        # Fallback : logging si win32 non disponible
        logging.info(f"NOTIFICATION: {title} - {message}")
    except Exception as e:
        logging.error(f"Erreur notification desktop: {e}")

def show_audio_help(parent, title, message):
    try:
        import win32com.client
        speaker = win32com.client.Dispatch("SAPI.SpVoice")
        speaker.Speak(message, 1)
    except Exception as e:
        logging.info(f"Aide audio indisponible: {e}")
    QMessageBox.information(parent, title, message)

def create_audio_help_button(parent, title, message):
    button = QPushButton("🔊")
    button.setFixedWidth(36)
    button.setToolTip("Cliquez pour écouter et afficher l'aide complète de cette page.")
    button.clicked.connect(lambda: show_audio_help(parent, title, message))
    return button

def normalize_ip(ip):
    if not ip:
        return ""
    return str(ip).replace("::ffff:", "").strip()

def get_connected_agent_ips():
    try:
        return {normalize_ip(info.get('ip')) for info in server.connected_agents.values() if normalize_ip(info.get('ip'))}
    except Exception:
        return set()

def get_connected_agent_ids():
    try:
        return {str(info.get('id')) for info in server.connected_agents.values() if info.get('id')}
    except Exception:
        return set()

# ============================================================
# Onglet Réseau
# ============================================================
class NetworkTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_main = parent
        self.network_scanner = NetworkScannerFixed()
        self.last_scan_devices = []
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Header avec contrôles
        header_layout = QHBoxLayout()
        
        # Titre
        title_label = QLabel("🌐 Surveillance Réseau")
        title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header_layout.addWidget(title_label)
        header_layout.addWidget(create_audio_help_button(
            self,
            "Aide Surveillance Réseau",
            "Page Réseau. Cette page affiche les machines prises en charge par l'agent CyberScan. Elle sert à sélectionner une machine gérée et consulter ses informations réseau détaillées : adresse IP, adresse MAC, nom d'hôte, constructeur, type d'appareil, statut, ports ouverts, score de risque, dates de première et dernière détection et état blacklist. Étapes : lancez d'abord une découverte réseau depuis le bouton Découverte Réseau, ouvrez ensuite l'onglet Réseau, sélectionnez une machine prise en charge dans le tableau, puis consultez ses détails et ses événements récents."
        ))
        
        header_layout.addStretch()
        
        # Boutons de contrôle
        self.start_btn = QPushButton("▶️ Démarrer")
        self.start_btn.setToolTip("Lance la surveillance automatique du réseau local détecté.")
        self.start_btn.clicked.connect(self.start_monitoring)
        header_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏸️ Arrêter")
        self.stop_btn.setToolTip("Arrête la surveillance réseau automatique.")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        header_layout.addWidget(self.stop_btn)
        
        self.refresh_btn = QPushButton("🔄 Actualiser")
        self.refresh_btn.setToolTip("Recharge la liste des appareils déjà détectés.")
        self.refresh_btn.clicked.connect(self.refresh_devices)
        header_layout.addWidget(self.refresh_btn)
        self.refresh_progress = QProgressBar()
        self.refresh_progress.setRange(0, 0)
        self.refresh_progress.setFixedWidth(120)
        self.refresh_progress.setVisible(False)
        header_layout.addWidget(self.refresh_progress)
        
        layout.addLayout(header_layout)
        help_label = QLabel("Cette page affiche les machines prises en charge par l'agent. Sélectionnez une machine pour voir ses détails réseau et ses événements.")
        help_label.setStyleSheet("color: #4a5568; background: #ebf8ff; padding: 6px; border-radius: 4px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        # Tableau des appareils
        self.devices_table = QTableWidget()
        self.setup_devices_table()
        layout.addWidget(self.devices_table)
        
        # Section détails
        details_group = QGroupBox("Détails de l'appareil sélectionné")
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setMinimumHeight(120)
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        # Section événements récents
        events_group = QGroupBox("Événements réseau récents")
        events_layout = QVBoxLayout()
        
        self.events_table = QTableWidget()
        self.setup_events_table()
        events_layout.addWidget(self.events_table)
        
        events_group.setLayout(events_layout)
        layout.addWidget(events_group)
        
        container = QWidget()
        container.setLayout(layout)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(container)
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)
        self.setLayout(outer_layout)
        
    def setup_devices_table(self):
        """Configure le tableau des appareils."""
        headers = ["IP", "MAC", "Hostname", "Constructeur", "Type", "Statut", "Ports", "Risque"]
        self.devices_table.setColumnCount(len(headers))
        self.devices_table.setHorizontalHeaderLabels(headers)
        
        # Ajuster les colonnes
        header = self.devices_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # MAC
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Hostname
        
        # Connecter le sélection
        self.devices_table.itemSelectionChanged.connect(self.on_device_selected)
        
    def setup_events_table(self):
        """Configure le tableau des événements."""
        headers = ["Timestamp", "Appareil", "Type", "Détails"]
        self.events_table.setColumnCount(len(headers))
        self.events_table.setHorizontalHeaderLabels(headers)
        
        header = self.events_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Détails
        
        self.events_table.setWordWrap(True)
        self.events_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.events_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.events_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.events_table.customContextMenuRequested.connect(self.show_events_context_menu)
        
        self.events_table.setMinimumHeight(150)
        
    def setup_timer(self):
        """Configure le timer de rafraîchissement."""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_devices)
        self.refresh_timer.start(10000)  # Rafraîchir toutes les 10 secondes
        
    def start_monitoring(self):
        """Démarre la surveillance réseau."""
        try:
            if not self.network_scanner:
                self.network_scanner = NetworkScannerFixed()
            
            # Callback pour les nouveaux appareils
            def on_new_devices(devices):
                self.show_new_devices_alert(devices)
                self.refresh_devices()
            
            self.network_scanner.start_monitoring(on_new_devices)
            
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            QMessageBox.information(self, "Surveillance", "Surveillance réseau démarrée")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur démarrage surveillance: {e}")
            
    def stop_monitoring(self):
        """Arrête la surveillance réseau."""
        try:
            if self.network_scanner:
                self.network_scanner.stop_monitoring()
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            QMessageBox.information(self, "Surveillance", "Surveillance réseau arrêtée")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur arrêt surveillance: {e}")
            
    def refresh_devices(self):
        """Rafraîchit la liste des appareils."""
        try:
            if not self.network_scanner:
                self.network_scanner = NetworkScannerFixed()
            
            self.refresh_progress.setVisible(True)
            QApplication.processEvents()
            devices = [d for d in self.apply_support_status(self.last_scan_devices) if d.get('support_status') == 'pris en charge']
            self.populate_devices_table(devices)
            self.refresh_events()
            self.refresh_progress.setVisible(False)
            
        except Exception as e:
            logging.error(f"Erreur rafraîchissement appareils: {e}")
            self.refresh_progress.setVisible(False)
    
    def apply_support_status(self, devices):
        """Ajoute le statut pris en charge / non pris en charge selon les agents connectés."""
        try:
            supported_ips = get_connected_agent_ips()
            updated = []
            for device in devices:
                item = dict(device)
                item['support_status'] = 'pris en charge' if normalize_ip(item.get('ip_address')) in supported_ips else 'non pris en charge'
                updated.append(item)
            self.last_scan_devices = updated
            return updated
        except Exception as e:
            logging.error(f"Erreur calcul prise en charge: {e}")
            return devices
            
    def populate_devices_table(self, devices):
        """Remplit le tableau des appareils."""
        self.devices_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            # IP
            self.devices_table.setItem(row, 0, QTableWidgetItem(device.get('ip_address', '')))
            
            # MAC
            self.devices_table.setItem(row, 1, QTableWidgetItem(device.get('mac_address', '')))
            
            # Hostname
            self.devices_table.setItem(row, 2, QTableWidgetItem(device.get('hostname', '')))
            
            # Constructeur
            self.devices_table.setItem(row, 3, QTableWidgetItem(device.get('manufacturer', '')))
            
            # Type
            device_type = device.get('device_type', '')
            type_item = QTableWidgetItem(device_type)
            
            # Couleur selon le type
            type_colors = {
                'computer': '#38a169',
                'server': '#3182ce',
                'router': '#d69e2e',
                'printer': '#805ad5',
                'mobile': '#ed8936',
                'iot_device': '#9f7aea',
                'unknown': '#718096'
            }
            color = type_colors.get(device_type, '#718096')
            type_item.setBackground(QBrush(QColor(color)))
            
            self.devices_table.setItem(row, 4, type_item)
            
            # Statut de prise en charge par agent
            status = device.get('support_status', 'non pris en charge')
            status_item = QTableWidgetItem(status.upper())
            
            if status == 'pris en charge':
                status_item.setBackground(QBrush(QColor('#38a169')))
            else:
                status_item.setBackground(QBrush(QColor('#dd6b20')))
                
            self.devices_table.setItem(row, 5, status_item)
            
            # Ports
            open_ports = json.loads(device.get('open_ports', '[]'))
            ports_text = f"{len(open_ports)} ports" if open_ports else "Aucun"
            if len(open_ports) > 5:
                ports_text += f" ({open_ports[:3]}...)"
            self.devices_table.setItem(row, 6, QTableWidgetItem(ports_text))
            
            # Risque
            risk_score = device.get('risk_score', 0)
            risk_item = QTableWidgetItem(str(risk_score))
            
            if risk_score >= 7:
                risk_item.setBackground(QBrush(QColor('#e53e3e')))
            elif risk_score >= 4:
                risk_item.setBackground(QBrush(QColor('#dd6b20')))
            else:
                risk_item.setBackground(QBrush(QColor('#38a169')))
                
            self.devices_table.setItem(row, 7, risk_item)
            
    def refresh_events(self):
        """Rafraîchit les événements récents."""
        try:
            if not self.network_scanner:
                return
                
            events = self.network_scanner.get_recent_events(20)
            self.populate_events_table(events)
            
        except Exception as e:
            logging.error(f"Erreur rafraîchissement événements: {e}")
            
    def populate_events_table(self, events):
        """Remplit le tableau des événements."""
        self.events_table.setRowCount(len(events))
        
        for row, event in enumerate(events):
            # Timestamp
            timestamp = event.get('timestamp', '')
            self.events_table.setItem(row, 0, QTableWidgetItem(timestamp))
            
            # Appareil
            device_ip = event.get('device_ip', '')
            self.events_table.setItem(row, 1, QTableWidgetItem(device_ip))
            
            # Type (Traduction en français)
            event_type = event.get('event_type', '')
            type_translations = {
                'new_device': 'Nouvel appareil',
                'device_offline': 'Appareil hors ligne',
                'ports_opened': 'Nouveaux ports ouverts',
                'blacklisted': 'Mis sur liste noire',
                'unblacklisted': 'Retiré de la liste noire'
            }
            display_type = type_translations.get(event_type, event_type)
            type_item = QTableWidgetItem(display_type)
            
            # Couleur selon le type
            type_colors = {
                'new_device': '#38a169',
                'device_offline': '#e53e3e',
                'ports_opened': '#dd6b20',
                'blacklisted': '#e53e3e',
                'unblacklisted': '#38a169'
            }
            color = type_colors.get(event_type, '#718096')
            type_item.setBackground(QBrush(QColor(color)))
            self.events_table.setItem(row, 2, type_item)
            
            # Détails (Formatage en français)
            event_data = json.loads(event.get('event_data', '{}'))
            details_text = ""
            for key, value in event_data.items():
                if key == "manufacturer": details_text += f"Constructeur: {value}\n"
                elif key == "device_type": details_text += f"Type d'appareil: {value}\n"
                elif key == "os_guess": details_text += f"Système: {value}\n"
                elif key == "open_ports": details_text += f"Ports ouverts: {value}\n"
                elif key == "status": details_text += f"Statut: {value}\n"
                elif key == "ports": details_text += f"Ports: {value}\n"
                else: details_text += f"{key.capitalize()}: {value}\n"
            
            details_text = details_text.strip()
            if not details_text:
                details_text = "Aucun détail supplémentaire."
                
            self.events_table.setItem(row, 3, QTableWidgetItem(details_text))
            
        self.events_table.resizeRowsToContents()
            
    def on_device_selected(self):
        """Gère la sélection d'un appareil."""
        try:
            current_row = self.devices_table.currentRow()
            if current_row < 0:
                return
                
            ip_item = self.devices_table.item(current_row, 0)
            if not ip_item:
                return
                
            ip = ip_item.text()
            
            if not self.network_scanner:
                return
                
            # Récupérer les détails complets du dernier scan uniquement
            devices = self.last_scan_devices
            for device in devices:
                if device.get('ip_address') == ip:
                    self.show_device_details(device)
                    break
                    
        except Exception as e:
            logging.error(f"Erreur sélection appareil: {e}")
            
    def show_device_details(self, device):
        """Affiche les détails d'un appareil."""
        details = f"""
📍 IP: {device.get('ip_address', 'N/A')}
🔌 MAC: {device.get('mac_address', 'N/A')}
🖥️ Hostname: {device.get('hostname', 'N/A')}
🏭 Constructeur: {device.get('manufacturer', 'N/A')}
📱 Type: {device.get('device_type', 'N/A')}
⚡ Statut: {device.get('support_status', 'non pris en charge').upper()}
🔓 Ports ouverts: {len(json.loads(device.get('open_ports', '[]')))}
⚠️ Score de risque: {device.get('risk_score', 0)}/10
🕐 Première vue: {device.get('first_seen', 'N/A')}
🕐 Dernière vue: {device.get('last_seen', 'N/A')}
🚫 Blacklist: {'Oui' if device.get('is_blacklisted') else 'Non'}
        """
        
        self.details_text.setPlainText(details.strip())
        
    def show_new_devices_alert(self, devices):
        """Affiche une alerte pour les nouveaux appareils."""
        if not devices:
            return
            
        device_names = []
        for device in devices:
            name = device.get('hostname', device.get('ip_address', 'Unknown'))
            device_names.append(f"• {name} ({device.get('ip_address')})")
        
        title = f"🔍 {len(devices)} nouveau(x) appareil(x) détecté(s)"
        message = "Nouveaux appareils sur le réseau:\n\n" + "\n".join(device_names[:5])
        
        if len(devices) > 5:
            message += f"\n\n... et {len(devices) - 5} autre(s)"
            
        # Afficher la notification desktop
        show_desktop_notification(title, message, "info")
        
        # Mettre à jour le badge dans l'interface si disponible
        if hasattr(self.parent_main, 'update_network_badge'):
            self.parent_main.update_network_badge(len(devices))

    def show_events_context_menu(self, position):
        """Affiche le menu contextuel pour les événements réseau."""
        selected_items = self.events_table.selectedItems()
        if not selected_items:
            return
            
        menu = QMenu()
        interpret_action = menu.addAction("Interpréter avec l'IA")
        
        action = menu.exec(self.events_table.viewport().mapToGlobal(position))
        if action == interpret_action:
            self.interpret_events_with_ai()
            
    def interpret_events_with_ai(self):
        """Récupère les événements sélectionnés et appelle l'IA pour les interpréter."""
        selected_rows = list(set([item.row() for item in self.events_table.selectedItems()]))
        if not selected_rows:
            return
            
        events_text = ""
        for row in selected_rows:
            timestamp = self.events_table.item(row, 0).text()
            appareil = self.events_table.item(row, 1).text()
            type_evt = self.events_table.item(row, 2).text()
            details = self.events_table.item(row, 3).text()
            events_text += f"- [{timestamp}] Appareil: {appareil}, Type: {type_evt}, Détails: {details}\n"
            
        # Afficher un message de chargement
        QMessageBox.information(self, "Analyse en cours", "L'IA analyse les événements sélectionnés. Veuillez patienter...")
        
        def run_analysis():
            try:
                result = ia_analyzer.analyze_network_events_with_ai(self.db, events_text)
                return result
            except Exception as e:
                return {"summary": "Erreur", "details": str(e), "recommendations": []}
                
        def on_analysis_complete(future):
            try:
                result = future.result()
                summary = result.get('summary', 'Aucun résumé')
                details = result.get('details', '')
                recs = result.get('recommendations', [])
                
                msg = f"<b>Résumé :</b><br>{summary}<br><br><b>Analyse :</b><br>{details}<br><br><b>Recommandations :</b><br>"
                for r in recs:
                    msg += f"- {r}<br>"
                    
                QMetaObject.invokeMethod(self, "_show_ai_result", Qt.ConnectionType.QueuedConnection, Q_ARG(str, msg))
            except Exception as e:
                QMetaObject.invokeMethod(self, "_show_ai_result", Qt.ConnectionType.QueuedConnection, Q_ARG(str, f"Erreur lors de l'analyse : {e}"))
                
        import concurrent.futures
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_analysis)
        future.add_done_callback(on_analysis_complete)

    @pyqtSlot(str)
    def _show_ai_result(self, html_msg):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Interprétation IA")
        msg_box.setTextFormat(Qt.TextFormat.RichText)
        msg_box.setText(html_msg)
        msg_box.exec()

# ============================================================
# Onglet Trafic
# ============================================================
class TrafficTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_main = parent
        self.traffic_monitor = None
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Header avec contrôles
        header_layout = QHBoxLayout()
        
        # Titre
        title_label = QLabel("📊 Surveillance Trafic")
        title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header_layout.addWidget(title_label)
        header_layout.addWidget(create_audio_help_button(
            self,
            "Aide Surveillance Trafic",
            "Page Trafic. Cette page sert à surveiller les connexions réseau en temps réel. En haut, les boutons Démarrer, Arrêter et Actualiser permettent de lancer la surveillance, l'arrêter ou recharger les données. La section Statistiques indique le nombre total de connexions, les connexions externes, les connexions suspectes et les alertes récentes. Le tableau des connexions affiche l'heure, le protocole, l'adresse locale, l'adresse distante, le statut, le processus et le niveau de risque. Le tableau des alertes affiche les événements suspects, leur sévérité, les adresses concernées, le processus et les détails. Étapes : cliquez sur Démarrer pour surveiller, observez les statistiques, sélectionnez une connexion ou une alerte pour analyser le trafic, puis cliquez sur Arrêter lorsque la surveillance n'est plus nécessaire."
        ))
        
        header_layout.addStretch()
        
        # Boutons de contrôle
        self.start_btn = QPushButton("▶️ Démarrer")
        self.start_btn.clicked.connect(self.start_monitoring)
        header_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏸️ Arrêter")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        header_layout.addWidget(self.stop_btn)
        
        self.refresh_btn = QPushButton("🔄 Actualiser")
        self.refresh_btn.clicked.connect(self.refresh_data)
        header_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Statistiques en temps réel
        stats_group = QGroupBox("Statistiques en temps réel")
        stats_layout = QGridLayout()
        
        self.total_connections_label = QLabel("0")
        self.external_connections_label = QLabel("0")
        self.suspicious_connections_label = QLabel("0")
        self.alerts_label = QLabel("0")
        
        stats_layout.addWidget(QLabel("Connexions totales:"), 0, 0)
        stats_layout.addWidget(self.total_connections_label, 0, 1)
        stats_layout.addWidget(QLabel("Connexions externes:"), 0, 2)
        stats_layout.addWidget(self.external_connections_label, 0, 3)
        stats_layout.addWidget(QLabel("Connexions suspectes:"), 1, 0)
        stats_layout.addWidget(self.suspicious_connections_label, 1, 1)
        stats_layout.addWidget(QLabel("Alertes récentes:"), 1, 2)
        stats_layout.addWidget(self.alerts_label, 1, 3)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Tableau des connexions
        self.connections_table = QTableWidget()
        self.setup_connections_table()
        layout.addWidget(self.connections_table)
        
        # Tableau des alertes
        alerts_group = QGroupBox("Alertes de trafic")
        alerts_layout = QVBoxLayout()
        
        self.alerts_table = QTableWidget()
        self.setup_alerts_table()
        alerts_layout.addWidget(self.alerts_table)
        
        alerts_group.setLayout(alerts_layout)
        layout.addWidget(alerts_group)
        
        container = QWidget()
        container.setLayout(layout)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(container)
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)
        self.setLayout(outer_layout)
        
    def setup_connections_table(self):
        """Configure le tableau des connexions."""
        headers = ["Timestamp", "Protocole", "Local IP:Port", "Distant IP:Port", "Statut", "Processus", "Risque"]
        self.connections_table.setColumnCount(len(headers))
        self.connections_table.setHorizontalHeaderLabels(headers)
        
        # Ajuster les colonnes
        header = self.connections_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Local
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Distant
        
        # Connecter la sélection
        self.connections_table.itemSelectionChanged.connect(self.on_connection_selected)
        
    def setup_alerts_table(self):
        """Configure le tableau des alertes."""
        headers = ["Timestamp", "Type", "Sévérité", "Local IP", "Distant IP", "Processus", "Détails"]
        self.alerts_table.setColumnCount(len(headers))
        self.alerts_table.setHorizontalHeaderLabels(headers)
        
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)  # Détails
        
        self.alerts_table.setMinimumHeight(180)
        
    def setup_timer(self):
        """Configure le timer de rafraîchissement."""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(5000)  # Rafraîchir toutes les 5 secondes
        
    def start_monitoring(self):
        """Démarre la surveillance du trafic."""
        try:
            if not self.traffic_monitor:
                self.traffic_monitor = TrafficMonitorSimple()
            
            # Callback pour les alertes
            def on_alert(alert):
                self.show_traffic_alert(alert)
                self.refresh_data()
            
            self.traffic_monitor.start_monitoring(on_alert)
            
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            QMessageBox.information(self, "Surveillance", "Surveillance du trafic démarrée")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur démarrage surveillance trafic: {e}")
            
    def stop_monitoring(self):
        """Arrête la surveillance du trafic."""
        try:
            if self.traffic_monitor:
                self.traffic_monitor.stop_monitoring()
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            QMessageBox.information(self, "Surveillance", "Surveillance du trafic arrêtée")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur arrêt surveillance trafic: {e}")
            
    def refresh_data(self):
        """Rafraîchit les données de trafic."""
        try:
            if not self.traffic_monitor:
                self.traffic_monitor = TrafficMonitorSimple()
            
            # Rafraîchir les statistiques
            self.refresh_statistics()
            
            # Rafraîchir les connexions
            self.refresh_connections()
            
            # Rafraîchir les alertes
            self.refresh_alerts()
            
        except Exception as e:
            logging.error(f"Erreur rafraîchissement données trafic: {e}")
            
    def refresh_statistics(self):
        """Rafraîchit les statistiques."""
        try:
            if not self.traffic_monitor:
                return
                
            stats = self.traffic_monitor.get_statistics()
            
            self.total_connections_label.setText(str(stats.get('connections_checked', 0)))
            self.external_connections_label.setText(str(stats.get('external_connections', 0)))
            self.suspicious_connections_label.setText(str(stats.get('suspicious_connections', 0)))
            self.alerts_label.setText(str(stats.get('alerts_last_hour', 0)))
            
        except Exception as e:
            logging.error(f"Erreur rafraîchissement statistiques: {e}")
            
    def refresh_connections(self):
        """Rafraîchit le tableau des connexions."""
        try:
            if not self.traffic_monitor:
                return
                
            connections = self.traffic_monitor.get_recent_connections(100)
            self.populate_connections_table(connections)
            
        except Exception as e:
            logging.error(f"Erreur rafraîchissement connexions: {e}")
            
    def populate_connections_table(self, connections):
        """Remplit le tableau des connexions."""
        self.connections_table.setRowCount(len(connections))
        
        for row, conn in enumerate(connections):
            # Timestamp - formaté en français avec conversion timezone
            timestamp_str = self._format_timestamp_fr(conn.get('timestamp', ''))
            self.connections_table.setItem(row, 0, QTableWidgetItem(timestamp_str))
            
            # Protocole
            protocol = conn.get('protocol', '')
            protocol_item = QTableWidgetItem(protocol)
            
            # Couleur selon le protocole
            if protocol == 'TCP':
                protocol_item.setBackground(QBrush(QColor('#3182ce')))
            elif protocol == 'UDP':
                protocol_item.setBackground(QBrush(QColor('#38a169')))
                
            self.connections_table.setItem(row, 1, protocol_item)
            
            # Local IP:Port
            local = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
            self.connections_table.setItem(row, 2, QTableWidgetItem(local))
            
            # Distant IP:Port
            remote = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"
            self.connections_table.setItem(row, 3, QTableWidgetItem(remote))
            
            # Statut
            status = conn.get('status', 'Unknown')
            status_item = QTableWidgetItem(status)
            
            if status == 'ESTABLISHED':
                status_item.setBackground(QBrush(QColor('#38a169')))
            elif status == 'LISTEN':
                status_item.setBackground(QBrush(QColor('#3182ce')))
            else:
                status_item.setBackground(QBrush(QColor('#718096')))
                
            self.connections_table.setItem(row, 4, status_item)
            
            # Processus
            process = conn.get('process_name', 'Unknown')
            self.connections_table.setItem(row, 5, QTableWidgetItem(process))
            
            # Risque
            risk_score = conn.get('risk_score', 0)
            risk_item = QTableWidgetItem(str(risk_score))
            
            if risk_score >= 7:
                risk_item.setBackground(QBrush(QColor('#e53e3e')))
            elif risk_score >= 4:
                risk_item.setBackground(QBrush(QColor('#dd6b20')))
            else:
                risk_item.setBackground(QBrush(QColor('#38a169')))
                
            self.connections_table.setItem(row, 6, risk_item)
            
    def refresh_alerts(self):
        """Rafraîchit le tableau des alertes."""
        try:
            if not self.traffic_monitor:
                return
                
            alerts = self.traffic_monitor.get_alerts(50)
            self.populate_alerts_table(alerts)
            
        except Exception as e:
            logging.error(f"Erreur rafraîchissement alertes: {e}")
            
    def _format_timestamp_fr(self, timestamp):
        """Convertit un timestamp en format français local."""
        try:
            if isinstance(timestamp, datetime):
                # Si c'est déjà un datetime, le formater directement
                return timestamp.strftime('%d/%m/%Y %H:%M:%S')
            elif isinstance(timestamp, str):
                # Parser la chaîne ISO (2026-05-31 17:47:58) ou avec timezone
                timestamp = timestamp.replace('T', ' ').replace('Z', '')
                # Essayer plusieurs formats
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%d/%m/%Y %H:%M:%S']:
                    try:
                        dt = datetime.strptime(timestamp[:19], fmt)
                        return dt.strftime('%d/%m/%Y %H:%M:%S')
                    except ValueError:
                        continue
                return timestamp[:19]  # Fallback: retourner les 19 premiers caractères
            else:
                return str(timestamp)[:19]
        except Exception:
            return str(timestamp)[:19] if timestamp else '--/--/---- --:--:--'
    
    def populate_alerts_table(self, alerts):
        """Remplit le tableau des alertes."""
        self.alerts_table.setRowCount(len(alerts))
        
        # Traduction des types d'alertes
        alert_translations = {
            'high_risk_connection': 'Connexion à haut risque',
            'suspicious_external_connection': 'Connexion externe suspecte',
            'suspicious_process_detected': 'Processus suspect détecté',
            'potential_backdoor': 'Porte dérobée potentielle',
            'irc_activity_detected': 'Activité IRC détectée',
            'new_connection': 'Nouvelle connexion',
            'closed_connection': 'Connexion fermée',
            'bandwidth_spike': 'Pic de bande passante',
            'unusual_pattern': 'Pattern inhabituel'
        }
        
        for row, alert in enumerate(alerts):
            # Timestamp - formaté en français
            timestamp_str = self._format_timestamp_fr(alert.get('timestamp', ''))
            self.alerts_table.setItem(row, 0, QTableWidgetItem(timestamp_str))
            
            # Type traduit en français
            alert_type = alert.get('alert_type', '')
            alert_type_fr = alert_translations.get(alert_type, alert_type)
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert_type_fr))
            
            # Sévérité traduite
            severity_translations = {
                'high': 'Élevée',
                'medium': 'Moyenne', 
                'low': 'Faible'
            }
            severity = alert.get('severity', '')
            severity_fr = severity_translations.get(severity, severity)
            severity_item = QTableWidgetItem(severity_fr)
            
            if severity == 'high':
                severity_item.setBackground(QBrush(QColor('#e53e3e')))
            elif severity == 'medium':
                severity_item.setBackground(QBrush(QColor('#dd6b20')))
            else:
                severity_item.setBackground(QBrush(QColor('#38a169')))
                
            self.alerts_table.setItem(row, 2, severity_item)
            
            # Local IP
            local_ip = alert.get('local_ip', '')
            self.alerts_table.setItem(row, 3, QTableWidgetItem(local_ip))
            
            # Distant IP
            remote_ip = alert.get('remote_ip', '')
            self.alerts_table.setItem(row, 4, QTableWidgetItem(remote_ip))
            
            # Processus
            process = alert.get('process_name', '')
            self.alerts_table.setItem(row, 5, QTableWidgetItem(process))
            
            # Détails
            details = alert.get('details', '{}')
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except:
                    details = {}
            
            details_text = ', '.join([f"{k}: {v}" for k, v in details.items()])
            self.alerts_table.setItem(row, 6, QTableWidgetItem(details_text))
            
    def on_connection_selected(self):
        """Gère la sélection d'une connexion."""
        try:
            current_row = self.connections_table.currentRow()
            if current_row < 0:
                return
                
            # Logique pour afficher les détails d'une connexion
            # (peut être étendue plus tard)
            
        except Exception as e:
            logging.error(f"Erreur sélection connexion: {e}")
            
    def show_traffic_alert(self, alert):
        """Affiche une alerte de trafic."""
        try:
            title = f"🚨 Alerte Trafic: {alert.get('type', 'Unknown')}"
            message = f"""
Type: {alert.get('type', 'Unknown')}
Sévérité: {alert.get('severity', 'Unknown')}
Local: {alert.get('local_ip', 'N/A')}
Distant: {alert.get('remote_ip', 'N/A')}
Processus: {alert.get('process_name', 'N/A')}
Détails: {alert.get('details', {})}
            """.strip()
            
            # Afficher la notification desktop
            show_desktop_notification(title, message, "warning")
            
            # Mettre à jour le badge dans l'interface si disponible
            if hasattr(self.parent_main, 'update_traffic_badge'):
                self.parent_main.update_traffic_badge(1)
                
        except Exception as e:
            logging.error(f"Erreur affichage alerte trafic: {e}")

def score_description(score):
    if score is None: return "Aucun scan effectué"
    if score <= 20: return "Failles exploitables immédiatement. Action urgente requise."
    if score <= 40: return "Plusieurs vulnérabilités majeures détectées."
    if score <= 60: return "Vulnérabilités modérées. Des améliorations sont nécessaires."
    if score <= 80: return "Bonne sécurité. Quelques points d'amélioration."
    return "Sécurité robuste. Continuez la surveillance."

# ============================================================
# Dialogue Paramètres API
# ============================================================
class ApiSettingsDialog(QDialog):
    def __init__(self, db):
        super().__init__()
        self.setWindowTitle("Paramètres")
        self.resize(500, 450)
        self.db = db
        
        main_layout = QVBoxLayout(self)
        
        # Onglets
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # --- Onglet Clés API ---
        api_tab = QWidget()
        api_layout = QFormLayout(api_tab)
        
        self.groq_input_1 = QLineEdit()
        self.groq_input_1.setText(self.db.get_api_key("Groq_1") or self.db.get_api_key("Groq") or "")
        self.groq_input_1.setEchoMode(QLineEdit.EchoMode.Password)
        api_layout.addRow("Clé API Groq 1:", self.groq_input_1)
        
        self.groq_input_2 = QLineEdit()
        self.groq_input_2.setText(self.db.get_api_key("Groq_2") or "")
        self.groq_input_2.setEchoMode(QLineEdit.EchoMode.Password)
        api_layout.addRow("Clé API Groq 2:", self.groq_input_2)
        
        self.groq_input_3 = QLineEdit()
        self.groq_input_3.setText(self.db.get_api_key("Groq_3") or "")
        self.groq_input_3.setEchoMode(QLineEdit.EchoMode.Password)
        api_layout.addRow("Clé API Groq 3:", self.groq_input_3)
        
        self.claude_input = QLineEdit()
        self.claude_input.setText(self.db.get_api_key("Claude") or "")
        self.claude_input.setEchoMode(QLineEdit.EchoMode.Password)
        api_layout.addRow("Clé API Claude:", self.claude_input)
        
        self.vt_input = QLineEdit()
        self.vt_input.setText(self.db.get_api_key("VirusTotal") or "")
        self.vt_input.setEchoMode(QLineEdit.EchoMode.Password)
        api_layout.addRow("Clé API VirusTotal:", self.vt_input)
        
        self.hibp_input = QLineEdit()
        self.hibp_input.setText(self.db.get_api_key("HaveIBeenPwned") or "")
        self.hibp_input.setEchoMode(QLineEdit.EchoMode.Password)
        api_layout.addRow("Clé API HaveIBeenPwned:", self.hibp_input)
        
        self.default_api_combo = QComboBox()
        self.default_api_combo.addItems(["Groq_1", "Groq_2", "Groq_3", "Claude"])
        default_val = self.db.get_api_key("Default_API") or "Groq_1"
        self.default_api_combo.setCurrentText(default_val)
        api_layout.addRow("API IA par défaut:", self.default_api_combo)
        
        tabs.addTab(api_tab, "Clés API")
        
        # --- Onglet Programmation ---
        schedule_tab = QWidget()
        sched_layout = QFormLayout(schedule_tab)
        
        self.schedule_enabled = QCheckBox("Activer le scan automatique programmé")
        saved_time = self.db.get_api_key("ScheduledScanTime")
        self.schedule_enabled.setChecked(bool(saved_time))
        sched_layout.addRow(self.schedule_enabled)
        
        self.schedule_time = QTimeEdit()
        if saved_time:
            parts = saved_time.split(":")
            if len(parts) == 2:
                self.schedule_time.setTime(QTime(int(parts[0]), int(parts[1])))
        else:
            self.schedule_time.setTime(QTime(2, 0))  # Par défaut 02:00
        sched_layout.addRow("Heure du scan automatique:", self.schedule_time)
        
        sched_info = QLabel(
            "Quand activé, toutes les machines connectées seront\n"
            "scannées automatiquement à l'heure programmée.\n"
            "Un rapport PDF sera déposé sur le bureau de chaque machine."
        )
        sched_info.setStyleSheet("color: #718096; font-size: 11px;")
        sched_layout.addRow(sched_info)
        
        tabs.addTab(schedule_tab, "Programmation")
        
        # --- Onglet Légende Scores ---
        legend_tab = QWidget()
        legend_layout = QVBoxLayout(legend_tab)
        
        legend_items = [
            ("0 — 20", "#c53030", "CRITIQUE", "Failles exploitables immédiatement"),
            ("21 — 40", "#dd6b20", "ÉLEVÉ", "Plusieurs vulnérabilités majeures"),
            ("41 — 60", "#d69e2e", "MOYEN", "Vulnérabilités modérées"),
            ("61 — 80", "#38a169", "BON", "Bonne sécurité, quelques améliorations"),
            ("81 — 100", "#276749", "EXCELLENT", "Sécurité robuste"),
        ]
        for range_txt, color, label, desc in legend_items:
            frame = QFrame()
            frame.setStyleSheet(f"background-color: {color}20; border-left: 4px solid {color}; padding: 6px; margin: 2px;")
            fl = QHBoxLayout(frame)
            fl.addWidget(QLabel(f"<b style='color:{color}'>{range_txt}</b>"))
            fl.addWidget(QLabel(f"<b>{label}</b> — {desc}"))
            fl.addStretch()
            legend_layout.addWidget(frame)
        
        legend_layout.addStretch()
        tabs.addTab(legend_tab, "Légende Scores")
        
        # Bouton sauvegarder
        save_btn = QPushButton("Sauvegarder")
        save_btn.setStyleSheet("padding: 8px; font-weight: bold;")
        save_btn.clicked.connect(self.save_keys)
        main_layout.addWidget(save_btn)

    def save_keys(self):
        self.db.set_api_key("Groq_1", self.groq_input_1.text())
        self.db.set_api_key("Groq_2", self.groq_input_2.text())
        self.db.set_api_key("Groq_3", self.groq_input_3.text())
        self.db.set_api_key("Claude", self.claude_input.text())
        self.db.set_api_key("VirusTotal", self.vt_input.text())
        self.db.set_api_key("HaveIBeenPwned", self.hibp_input.text())
        self.db.set_api_key("Default_API", self.default_api_combo.currentText())
        
        if self.schedule_enabled.isChecked():
            time_str = self.schedule_time.time().toString("HH:mm")
            self.db.set_api_key("ScheduledScanTime", time_str)
        else:
            self.db.set_api_key("ScheduledScanTime", "")
        
        QMessageBox.information(self, "Succès", "Paramètres sauvegardés avec succès !")
        self.accept()

# ============================================================
# Onglet Sécurité - Détails de protection
# ============================================================
class SecurityTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_main = parent
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)
        
        # Sous-onglets pour chaque catégorie
        self.sub_tabs = QTabWidget()
        self.sub_tabs.setStyleSheet(
            "QTabBar::tab { padding: 6px 14px; font-weight: bold; }"
            "QTabBar::tab:selected { background: #2d3748; color: white; }")
        
        # --- Sous-onglet Ports et Connexions ---
        self.ports_tab = QWidget()
        self.setup_ports_tab()
        self.sub_tabs.addTab(self.ports_tab, "🌐 Ports et Connexions")
        
        # --- Sous-onglet Fichiers Système ---
        self.integrity_tab = QWidget()
        self.setup_integrity_tab()
        self.sub_tabs.addTab(self.integrity_tab, "📁 Fichiers Système")
        
        # --- Sous-onglet Activités Suspectes ---
        self.logs_tab = QWidget()
        self.setup_logs_tab()
        self.sub_tabs.addTab(self.logs_tab, "⚠️ Activités à Vérifier")
        
        # Info contextuelle simplifiée (sans bouton audio intrusif)
        help_label = QLabel(
            "💡 Ces onglets montrent les détails de sécurité détectés sur la machine sélectionnée.\n"
            "🔍 Ports ouverts = connexions réseau actives | "
            "📁 Fichiers = modifications importantes | "
            "⚠️ Activités = comportements inhabituels à vérifier"
        )
        help_label.setStyleSheet("color: #4a5568; background: #ebf8ff; padding: 10px; border-radius: 6px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        layout.addWidget(self.sub_tabs)
        
        # Layout pour aide audio (ajouté dynamiquement)
        self.audio_help_layout = QHBoxLayout()
        self.audio_help_layout.addStretch()
        layout.addLayout(self.audio_help_layout)
        
        self.setLayout(layout)
    
    def add_audio_help(self, title, message):
        """Ajoute un bouton d'aide audio."""
        from app import create_audio_help_button
        self.audio_help_layout.addWidget(create_audio_help_button(self, title, message))
    
    def make_scrollable(self, tab, content_layout):
        container = QWidget()
        container.setLayout(content_layout)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(container)
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)
        tab.setLayout(outer_layout)
    
    def setup_ports_tab(self):
        """Configure le sous-onglet Ports et Connexions."""
        layout = QVBoxLayout()
        
        # Header simplifié
        header = QHBoxLayout()
        title = QLabel("🌐 Connexions Réseau Détectées")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.addWidget(title)
        header.addStretch()
        
        self.ports_risk_label = QLabel("Niveau: —")
        self.ports_risk_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.ports_risk_label.setToolTip("Évaluation du risque basée sur les ports ouverts")
        header.addWidget(self.ports_risk_label)
        layout.addLayout(header)
        
        # Aide contextuelle simplifiée
        help_label = QLabel(
            "💡 Liste des connexions réseau actives sur la machine. "
            "Un port ouvert = une porte possible pour les attaquants. "
            "Les ports marqués 'Élevé' nécessitent votre attention."
        )
        help_label.setStyleSheet("color: #4a5568; background: #f0fff4; padding: 10px; border-radius: 6px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        # Tableau des ports ouverts
        self.ports_table = QTableWidget()
        port_headers = ["Port", "Service", "État", "Bannière", "Risque"]
        self.ports_table.setColumnCount(len(port_headers))
        self.ports_table.setHorizontalHeaderLabels(port_headers)
        ph = self.ports_table.horizontalHeader()
        ph.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        ph.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.ports_table.setMinimumHeight(250)
        layout.addWidget(self.ports_table)
        
        # Recommandations
        reco_group = QGroupBox("Recommandations")
        reco_layout = QVBoxLayout()
        self.ports_reco_text = QTextEdit()
        self.ports_reco_text.setReadOnly(True)
        self.ports_reco_text.setMinimumHeight(100)
        self.ports_reco_text.setStyleSheet("font-size: 12px;")
        reco_layout.addWidget(self.ports_reco_text)
        reco_group.setLayout(reco_layout)
        layout.addWidget(reco_group)
        
        self.make_scrollable(self.ports_tab, layout)
    
    def setup_integrity_tab(self):
        """Configure le sous-onglet Fichiers Système."""
        layout = QVBoxLayout()
        
        # Header simplifié
        header = QHBoxLayout()
        title = QLabel("📁 Surveillance des Fichiers Importants")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.addWidget(title)
        header.addStretch()
        
        self.integrity_risk_label = QLabel("Niveau: —")
        self.integrity_risk_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        header.addWidget(self.integrity_risk_label)
        layout.addLayout(header)
        
        # Aide contextuelle simplifiée
        help_label = QLabel(
            "💡 Détection des modifications sur les fichiers système critiques. "
            "Un fichier modifié inhabituellement peut indiquer une infection. "
            "Compare l'état actuel avec une référence saine."
        )
        help_label.setStyleSheet("color: #4a5568; background: #fffaf0; padding: 10px; border-radius: 6px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        # Statistiques
        stats_layout = QHBoxLayout()
        self.integrity_stats = {
            'checked': QLabel("Fichiers vérifiés: —"),
            'ok': QLabel("Intacts: —"),
            'modified': QLabel("Modifiés: —"),
            'missing': QLabel("Manquants: —"),
        }
        for lbl in self.integrity_stats.values():
            lbl.setStyleSheet("font-size: 12px; padding: 4px 8px; background: #f7fafc; border-radius: 4px;")
            stats_layout.addWidget(lbl)
        layout.addLayout(stats_layout)
        
        # Tableau fichiers modifiés
        mod_group = QGroupBox("Fichiers modifiés (alertes)")
        mod_layout = QVBoxLayout()
        self.integrity_table = QTableWidget()
        int_headers = ["Fichier", "Date modification", "Ancien hash", "Nouveau hash"]
        self.integrity_table.setColumnCount(len(int_headers))
        self.integrity_table.setHorizontalHeaderLabels(int_headers)
        ih = self.integrity_table.horizontalHeader()
        ih.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        ih.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.integrity_table.setMinimumHeight(180)
        mod_layout.addWidget(self.integrity_table)
        mod_group.setLayout(mod_layout)
        layout.addWidget(mod_group)
        
        # Éléments au démarrage
        startup_group = QGroupBox("Éléments au démarrage Windows")
        startup_layout = QVBoxLayout()
        self.startup_table = QTableWidget()
        su_headers = ["Nom", "Chemin", "Hash"]
        self.startup_table.setColumnCount(len(su_headers))
        self.startup_table.setHorizontalHeaderLabels(su_headers)
        sh = self.startup_table.horizontalHeader()
        sh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        sh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.startup_table.setMinimumHeight(120)
        startup_layout.addWidget(self.startup_table)
        startup_group.setLayout(startup_layout)
        layout.addWidget(startup_group)
        
        # Recommandations
        reco_group = QGroupBox("Recommandations")
        reco_layout = QVBoxLayout()
        self.integrity_reco_text = QTextEdit()
        self.integrity_reco_text.setReadOnly(True)
        self.integrity_reco_text.setMinimumHeight(80)
        reco_layout.addWidget(self.integrity_reco_text)
        reco_group.setLayout(reco_layout)
        layout.addWidget(reco_group)
        
        self.make_scrollable(self.integrity_tab, layout)
    
    def setup_logs_tab(self):
        """Configure le sous-onglet Activités à Vérifier."""
        layout = QVBoxLayout()
        
        # Header simplifié
        header = QHBoxLayout()
        title = QLabel("⚠️ Activités Suspectes Détectées")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header.addWidget(title)
        header.addStretch()
        
        self.logs_risk_label = QLabel("Niveau: —")
        self.logs_risk_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        header.addWidget(self.logs_risk_label)
        layout.addLayout(header)
        
        # Aide contextuelle simplifiée
        help_label = QLabel(
            "💡 Analyse automatique des événements Windows suspects. "
            "Détecte les tentatives de connexion forcée, les programmes suspects, "
            "et les changements inhabituels de sécurité."
        )
        help_label.setStyleSheet("color: #4a5568; background: #ebf8ff; padding: 10px; border-radius: 6px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        # Résumé alertes
        summary_layout = QHBoxLayout()
        self.logs_summary = {
            'total': QLabel("Total alertes: —"),
            'critical': QLabel("Critiques: —"),
            'high': QLabel("Élevées: —"),
            'medium': QLabel("Moyennes: —"),
        }
        colors = {'total': '#2d3748', 'critical': '#c53030', 'high': '#dd6b20', 'medium': '#d69e2e'}
        for key, lbl in self.logs_summary.items():
            lbl.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {colors[key]}; padding: 4px 10px; background: #f7fafc; border-radius: 4px;")
            summary_layout.addWidget(lbl)
        layout.addLayout(summary_layout)
        
        # Tableau des alertes
        alerts_group = QGroupBox("Alertes de sécurité détectées")
        alerts_layout = QVBoxLayout()
        self.alerts_table = QTableWidget()
        alert_headers = ["Sévérité", "Règle", "Description", "Détails"]
        self.alerts_table.setColumnCount(len(alert_headers))
        self.alerts_table.setHorizontalHeaderLabels(alert_headers)
        ah = self.alerts_table.horizontalHeader()
        ah.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        ah.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.setMinimumHeight(200)
        alerts_layout.addWidget(self.alerts_table)
        alerts_group.setLayout(alerts_layout)
        layout.addWidget(alerts_group)
        
        # Connexions récentes
        logins_group = QGroupBox("Connexions récentes")
        logins_layout = QVBoxLayout()
        self.logins_table = QTableWidget()
        login_headers = ["Date/Heure", "Utilisateur", "Type", "IP source"]
        self.logins_table.setColumnCount(len(login_headers))
        self.logins_table.setHorizontalHeaderLabels(login_headers)
        lh = self.logins_table.horizontalHeader()
        lh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        lh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.logins_table.setMinimumHeight(150)
        logins_layout.addWidget(self.logins_table)
        logins_group.setLayout(logins_layout)
        layout.addWidget(logins_group)
        
        # Recommandations
        reco_group = QGroupBox("Recommandations")
        reco_layout = QVBoxLayout()
        self.logs_reco_text = QTextEdit()
        self.logs_reco_text.setReadOnly(True)
        self.logs_reco_text.setMinimumHeight(80)
        reco_layout.addWidget(self.logs_reco_text)
        reco_group.setLayout(reco_layout)
        layout.addWidget(reco_group)
        
        self.make_scrollable(self.logs_tab, layout)
    
    def update_from_scan(self, scan_data):
        """Met à jour tous les sous-onglets avec les données du dernier scan."""
        if not scan_data:
            return
        
        # Mettre à jour les ports
        port_data = scan_data.get('port_scan', {})
        if port_data and 'error' not in port_data:
            self.update_ports(port_data)
        
        # Mettre à jour l'intégrité
        integrity_data = scan_data.get('integrity_check', {})
        if integrity_data and 'error' not in integrity_data:
            self.update_integrity(integrity_data)
        
        # Mettre à jour les logs
        log_data = scan_data.get('log_analysis', {})
        if log_data and 'error' not in log_data:
            self.update_logs(log_data)
    
    def update_ports(self, data):
        """Met à jour le sous-onglet Ports."""
        # Risque global
        risk = data.get('risk_level', 'low')
        risk_colors = {'low': '#38a169', 'medium': '#d69e2e', 'high': '#dd6b20', 'critical': '#c53030'}
        self.ports_risk_label.setText(f"Risque: {risk.upper()}")
        self.ports_risk_label.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {risk_colors.get(risk, '#888')};")
        
        # Tableau
        open_ports = data.get('open_ports', [])
        self.ports_table.setRowCount(len(open_ports))
        for row, port_info in enumerate(open_ports):
            self.ports_table.setItem(row, 0, QTableWidgetItem(str(port_info['port'])))
            self.ports_table.setItem(row, 1, QTableWidgetItem(port_info.get('service', '?')))
            self.ports_table.setItem(row, 2, QTableWidgetItem(port_info.get('state', '?')))
            self.ports_table.setItem(row, 3, QTableWidgetItem(port_info.get('banner', '')[:80]))
            
            risk_item = QTableWidgetItem(port_info.get('risk', 'low').upper())
            risk_val = port_info.get('risk', 'low')
            if risk_val == 'high':
                risk_item.setForeground(QBrush(QColor('#c53030')))
            elif risk_val == 'medium':
                risk_item.setForeground(QBrush(QColor('#dd6b20')))
            self.ports_table.setItem(row, 4, risk_item)
        
        # Recommandations
        recos = data.get('recommendations', [])
        self.ports_reco_text.setPlainText('\n'.join(recos))
    
    def update_integrity(self, data):
        """Met à jour le sous-onglet Intégrité."""
        risk = data.get('risk_level', 'low')
        risk_colors = {'low': '#38a169', 'medium': '#d69e2e', 'high': '#dd6b20', 'critical': '#c53030'}
        self.integrity_risk_label.setText(f"Risque: {risk.upper()}")
        self.integrity_risk_label.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {risk_colors.get(risk, '#888')};")
        
        # Stats
        self.integrity_stats['checked'].setText(f"Vérifiés: {data.get('files_checked', 0)}")
        self.integrity_stats['ok'].setText(f"Intacts: {data.get('files_ok', 0)}")
        self.integrity_stats['modified'].setText(f"Modifiés: {len(data.get('files_modified', []))}")
        self.integrity_stats['missing'].setText(f"Manquants: {len(data.get('files_missing', []))}")
        
        # Fichiers modifiés
        modified = data.get('files_modified', [])
        self.integrity_table.setRowCount(len(modified))
        for row, f in enumerate(modified):
            import os as _os
            self.integrity_table.setItem(row, 0, QTableWidgetItem(_os.path.basename(f.get('path', ''))))
            self.integrity_table.setItem(row, 1, QTableWidgetItem(f.get('info', {}).get('modified', '?')))
            self.integrity_table.setItem(row, 2, QTableWidgetItem(f.get('old_hash', '?')))
            self.integrity_table.setItem(row, 3, QTableWidgetItem(f.get('new_hash', '?')))
        
        # Startup items
        startup = data.get('startup_items', [])
        self.startup_table.setRowCount(len(startup))
        for row, item in enumerate(startup):
            self.startup_table.setItem(row, 0, QTableWidgetItem(item.get('name', '')))
            self.startup_table.setItem(row, 1, QTableWidgetItem(item.get('path', '')))
            self.startup_table.setItem(row, 2, QTableWidgetItem(item.get('hash', '')[:20] + '...'))
        
        # Recommandations
        recos = data.get('recommendations', [])
        self.integrity_reco_text.setPlainText('\n'.join(recos))
    
    def update_logs(self, data):
        """Met à jour le sous-onglet Logs."""
        risk = data.get('risk_level', 'low')
        risk_colors = {'low': '#38a169', 'medium': '#d69e2e', 'high': '#dd6b20', 'critical': '#c53030'}
        self.logs_risk_label.setText(f"Risque: {risk.upper()}")
        self.logs_risk_label.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {risk_colors.get(risk, '#888')};")
        
        # Résumé
        summary = data.get('summary', {})
        self.logs_summary['total'].setText(f"Total: {summary.get('total_alerts', 0)}")
        self.logs_summary['critical'].setText(f"Critiques: {summary.get('critical', 0)}")
        self.logs_summary['high'].setText(f"Élevées: {summary.get('high', 0)}")
        self.logs_summary['medium'].setText(f"Moyennes: {summary.get('medium', 0)}")
        
        # Alertes
        alerts = data.get('alerts', [])
        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            sev = alert.get('severity', 'low')
            sev_item = QTableWidgetItem(sev.upper())
            sev_colors = {'critical': '#c53030', 'high': '#dd6b20', 'medium': '#d69e2e', 'low': '#38a169'}
            sev_item.setForeground(QBrush(QColor(sev_colors.get(sev, '#888'))))
            self.alerts_table.setItem(row, 0, sev_item)
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.get('rule', '')))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.get('description', '')))
            details = alert.get('details', [])
            details_str = '; '.join(details[:3]) if isinstance(details, list) else str(details)
            self.alerts_table.setItem(row, 3, QTableWidgetItem(details_str))
        
        # Connexions récentes
        logins = data.get('recent_logins', [])
        self.logins_table.setRowCount(len(logins))
        logon_types = {'2': 'Interactive', '3': 'Réseau', '4': 'Batch', '5': 'Service', 
                       '7': 'Unlock', '8': 'NetworkClear', '10': 'RDP', '11': 'CachedCreds'}
        for row, login in enumerate(logins):
            self.logins_table.setItem(row, 0, QTableWidgetItem(login.get('time', '')))
            self.logins_table.setItem(row, 1, QTableWidgetItem(login.get('user', '')))
            ltype = login.get('type', '?')
            self.logins_table.setItem(row, 2, QTableWidgetItem(logon_types.get(str(ltype), f'Type {ltype}')))
            self.logins_table.setItem(row, 3, QTableWidgetItem(login.get('source_ip', '-')))
        
        # Recommandations
        recos = data.get('recommendations', [])
        self.logs_reco_text.setPlainText('\n'.join(recos))


# ============================================================
# Fenêtre Principale
# ============================================================
class CyberScanAdmin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = CyberScanDB()
        
        # Déterminer le mode d'interface (simple ou expert)
        self.interface_mode = self.db.get_api_key("interface_mode") or "simple"
        
        # Afficher le wizard si première exécution
        if should_show_wizard(self.db):
            self.show_onboarding()
        
        # Mettre à jour le titre selon le mode
        mode_suffix = "Mode Simple" if self.interface_mode == "simple" else "Mode Expert"
        self.setWindowTitle(f"CyberScan - {mode_suffix}")
        self.resize(1000, 700)
        
        self.init_ui()
        
        # Démarrage du serveur WebSocket en arrière-plan
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        # Rafraichissement automatique
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_live_status)
        self.timer.start(3000)
        
        # Timer d'animation rapide (500ms) pour les indicateurs de scan
        self.anim_timer = QTimer()
        self.anim_timer.timeout.connect(self.update_animations)
        self.anim_timer.start(500)
    
    def show_onboarding(self):
        """Affiche le wizard de premier lancement."""
        wizard = OnboardingWizard(self.db, self)
        if wizard.exec() == QDialog.DialogCode.Accepted:
            # Mettre à jour le mode après le wizard
            self.interface_mode = wizard.get_selected_mode()
            logging.info(f"Wizard terminé - Mode sélectionné: {self.interface_mode}")
        else:
            # Wizard annulé - continuer avec les valeurs par défaut
            logging.info("Wizard annulé par l'utilisateur")
    
    def toggle_interface_mode(self):
        """Bascule entre mode Simple et Expert."""
        new_mode = "expert" if self.interface_mode == "simple" else "simple"
        self.db.set_api_key("interface_mode", new_mode)
        self.interface_mode = new_mode
        
        # Mettre à jour le titre
        mode_suffix = "Mode Simple" if new_mode == "simple" else "Mode Expert"
        self.setWindowTitle(f"CyberScan - {mode_suffix}")
        
        # Recharger l'interface
        QMessageBox.information(
            self, 
            "Mode changé", 
            f"Passage en {mode_suffix}.\nL'interface va se recharger."
        )
        self.init_ui()
    
    def get_visible_tabs(self):
        """Retourne les onglets à afficher selon le mode."""
        if self.interface_mode == "simple":
            return ["machines", "security"]  # Seulement 2 onglets essentiels
        return ["machines", "network", "traffic", "security"]  # Tous les onglets
    
    def get_visible_buttons(self):
        """Retourne les boutons à afficher selon le mode."""
        if self.interface_mode == "simple":
            return {
                "row1": ["refresh", "scan_quick", "details", "pdf"],
                "row2": ["api", "toggle_mode"]  # Mode simple: boutons essentiels + toggle
            }
        return {
            "row1": ["refresh", "scan_full", "scan_quick", "details", "pdf"],
            "row2": ["hibp", "network", "scan_all_full", "scan_all_quick", "api", "toggle_mode"]
        }

    def refresh_live_status(self):
        self.update_server_status()
        self.refresh_table()
        if hasattr(self, 'network_tab'):
            self.network_tab.refresh_devices()

    def update_server_status(self):
        try:
            with socket.create_connection(("127.0.0.1", 8765), timeout=0.3):
                self.server_status_label.setText("Serveur agents: actif :8765")
                self.server_status_label.setStyleSheet("color: #9ae6b4; font-size: 11px;")
        except Exception:
            self.server_status_label.setText("Serveur agents: inactif :8765")
            self.server_status_label.setStyleSheet("color: #feb2b2; font-size: 11px;")

    def init_ui(self):
        """Initialise l'interface utilisateur avec adaptation au mode Simple/Expert."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(8)
        
        # === HEADER ===
        header = QFrame()
        header.setStyleSheet("background-color: #1a365d; border-radius: 6px; padding: 12px;")
        header_layout = QHBoxLayout(header)
        
        # Titre adaptatif selon le mode
        title_text = "CyberScan — Sécurité Simplifiée" if self.interface_mode == "simple" else "CyberScan — Console Administrateur"
        title = QLabel(title_text)
        title.setStyleSheet("color: white; font-size: 18px; font-weight: bold;")
        header_layout.addWidget(title)
        
        # Badge mode
        mode_badge = QLabel(f"🟢 {self.interface_mode.upper()}")
        mode_badge.setStyleSheet("color: #9ae6b4; font-size: 11px; font-weight: bold; background: #276749; padding: 4px 10px; border-radius: 12px;")
        mode_badge.setToolTip("Cliquez sur 'Changer de mode' pour passer en mode Expert/Simple")
        header_layout.addWidget(mode_badge)
        
        # Info scan programmé
        self.schedule_label = QLabel("")
        self.schedule_label.setStyleSheet("color: #90cdf4; font-size: 11px;")
        header_layout.addWidget(self.schedule_label)
        header_layout.addStretch()
        
        # Compteurs
        self.count_label = QLabel("")
        self.count_label.setStyleSheet("color: #e2e8f0; font-size: 11px;")
        header_layout.addWidget(self.count_label)
        self.server_status_label = QLabel("Serveur: vérification...")
        self.server_status_label.setStyleSheet("color: #fbd38d; font-size: 11px;")
        header_layout.addWidget(self.server_status_label)
        main_layout.addWidget(header)
        
        # === PANNEAU SCORE SÉLECTIONNÉ (simplifié en mode simple) ===
        self.score_panel = QFrame()
        self.score_panel.setStyleSheet("background-color: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px;")
        score_layout = QHBoxLayout(self.score_panel)
        
        # Texte adaptatif
        default_text = "Sélectionnez une machine dans la liste" if self.interface_mode == "simple" else "Sélectionnez une machine"
        self.score_display = QLabel(default_text)
        self.score_display.setStyleSheet("font-size: 14px; font-weight: bold; color: #4a5568;")
        score_layout.addWidget(self.score_display)
        
        self.score_bar = QProgressBar()
        self.score_bar.setMinimum(0)
        self.score_bar.setMaximum(100)
        self.score_bar.setValue(0)
        self.score_bar.setTextVisible(True)
        self.score_bar.setFormat("%v / 100")
        self.score_bar.setFixedHeight(22)
        self.score_bar.setFixedWidth(200)
        score_layout.addWidget(self.score_bar)
        
        # Tooltip explicatif en mode simple
        if self.interface_mode == "simple":
            self.score_bar.setToolTip("📊 Score de sécurité:\n• 80-100: Excellent\n• 60-79: Bon\n• 40-59: Moyen\n• 20-39: Élevé\n• 0-19: Critique")
        
        self.score_interpretation = QLabel("")
        self.score_interpretation.setStyleSheet("font-size: 11px; color: #718096;")
        score_layout.addWidget(self.score_interpretation)
        score_layout.addStretch()
        main_layout.addWidget(self.score_panel)
        
        # === ONGLETS PRINCIPAUX (adaptés selon le mode) ===
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane { border: 1px solid #e2e8f0; border-radius: 6px; } "
                               "QTabBar::tab { background: #f7fafc; padding: 8px 16px; margin-right: 2px; } "
                               "QTabBar::tab:selected { background: #2c5282; color: white; }")
        
        # Onglet Machines (toujours présent)
        machines_tab = QWidget()
        machines_layout = QVBoxLayout(machines_tab)
        
        # Texte d'aide avec audio dans tous les modes
        if self.interface_mode == "simple":
            help_text = "💡 Liste des machines protégées. Cliquez sur une machine pour voir son score de sécurité."
            audio_title = "Aide Machines"
            audio_msg = ("Page Machines. Cette page liste toutes vos machines protégées. "
                        "La colonne 'État' montre si la machine est en ligne ou hors ligne. "
                        "La colonne 'Score' affiche sa note de sécurité de 0 à 100. "
                        "Sélectionnez une machine, puis cliquez sur 'Analyse Rapide' pour l'analyser.")
        else:
            help_text = "Cette page liste toutes les machines détectées avec leur statut de prise en charge par l'agent."
            audio_title = "Aide Machines"
            audio_msg = "Page Machines. Cette page liste toutes les machines connues ou détectées sur le réseau."
        
        machines_help = QHBoxLayout()
        help_label = QLabel(help_text)
        help_label.setWordWrap(True)
        machines_help.addWidget(help_label)
        machines_help.addStretch()
        
        # Bouton aide audio dans tous les modes
        machines_help.addWidget(create_audio_help_button(self, audio_title, audio_msg))
        machines_layout.addLayout(machines_help)
        
        # === TABLE DES MACHINES ===
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Nom", "IP", "Système", "État", "Score", "Vu le"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
        
        # Tooltip sur les en-têtes en mode simple
        if self.interface_mode == "simple":
            self.table.horizontalHeaderItem(4).setToolTip("Score de sécurité: plus c'est élevé, mieux c'est!")
        
        machines_layout.addWidget(self.table)
        self.tabs.addTab(machines_tab, "💻 Machines")
        
        # Onglets conditionnels selon le mode
        visible_tabs = self.get_visible_tabs()
        
        # En mode Simple: Dashboard en premier
        if self.interface_mode == "simple":
            self.dashboard_tab = DashboardTab(self)
            self.tabs.addTab(self.dashboard_tab, "📊 Accueil")
        
        if "network" in visible_tabs:
            self.network_tab = NetworkTab(self)
            self.tabs.addTab(self.network_tab, "🌐 Réseau")
        
        if "traffic" in visible_tabs:
            self.traffic_tab = TrafficTab(self)
            self.tabs.addTab(self.traffic_tab, "📊 Trafic")
        
        if "security" in visible_tabs:
            self.security_tab = SecurityTab(self)
            # Nom simplifié en mode simple avec aide audio
            tab_name = "🔒 Détails" if self.interface_mode == "simple" else "🛡️ Sécurité"
            self.tabs.addTab(self.security_tab, tab_name)
            
            # Ajouter aide audio pour l'onglet Sécurité/Détails dans tous les modes
            if hasattr(self.security_tab, 'add_audio_help'):
                if self.interface_mode == "simple":
                    self.security_tab.add_audio_help(
                        "Aide Détails",
                        ("Onglet Détails. Cette page montre les résultats détaillés de la dernière analyse. "
                         "L'onglet Ports montre les connexions réseau. "
                         "L'onglet Fichiers montre les changements importants. "
                         "L'onglet Activités montre les comportements suspects détectés.")
                    )
                else:
                    self.security_tab.add_audio_help(
                        "Aide Sécurité",
                        "Onglet Sécurité. Trois sous-onglets: Ports et Connexions, Fichiers Système, et Activités à Vérifier."
                    )
        
        main_layout.addWidget(self.tabs)
        
        # === BARRE DE STATUT MODE SIMPLE (visuelle et informative) ===
        if self.interface_mode == "simple":
            status_frame = QFrame()
            status_frame.setStyleSheet("""
                QFrame {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 10px;
                    padding: 15px;
                    color: white;
                    margin: 5px 0;
                }
                QLabel { color: white; }
            """)
            status_layout = QHBoxLayout(status_frame)
            
            # Icône et titre
            simple_icon = QLabel("🎯")
            simple_icon.setFont(QFont("Segoe UI", 32))
            status_layout.addWidget(simple_icon)
            
            simple_title = QLabel("<b>Mode Simple activé</b><br>"
                                   "Interface simplifiée avec actions essentielles. "
                                   "Cliquez sur 'Mode Expert' pour plus d'options.")
            simple_title.setStyleSheet("font-size: 13px; color: white;")
            simple_title.setWordWrap(True)
            status_layout.addWidget(simple_title)
            status_layout.addStretch()
            
            # Badge vert
            simple_badge = QLabel("✓ Actif")
            simple_badge.setStyleSheet("""
                background: #48bb78;
                color: white;
                padding: 5px 15px;
                border-radius: 15px;
                font-weight: bold;
                font-size: 11px;
            """)
            status_layout.addWidget(simple_badge)
            
            main_layout.addWidget(status_frame)
        
        # === BOUTONS D'ACTIONS (adaptatifs) ===
        btn_frame = QFrame()
        btn_frame.setStyleSheet("background-color: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 6px;")
        btn_grid = QGridLayout(btn_frame)
        btn_grid.setSpacing(6)
        
        visible_buttons = self.get_visible_buttons()
        
        # Configuration des boutons disponibles
        buttons_config = {
            "refresh": ("🔄 Actualiser", "Met à jour la liste des machines", self.refresh_current_view, None),
            "scan_full": ("🔍 Analyse Complète", "Analyse approfondie (~60-90s)", lambda: self.request_rescan(mode='full'), "background-color: #2c5282; color: white; font-weight: bold;"),
            "scan_quick": ("⚡ Analyse Rapide", "Analyse rapide (~15-20s)", lambda: self.request_rescan(mode='quick'), "background-color: #38a169; color: white; font-weight: bold;"),
            "details": ("📋 Voir le Rapport", "Affiche les détails de sécurité", self.show_details, None),
            "pdf": ("📄 Exporter PDF", "Sauvegarde le rapport en PDF", self.export_pdf, None),
            "hibp": ("📧 Emails Compromis", "Vérifie si des emails sont piratés", self.check_emails, "background-color: #744210; color: white;"),
            "network": ("🔍 Explorer Réseau", "Découverte des appareils réseau", self.run_network_scan, None),
            "scan_all_full": ("🔍 Tout Analyser (Complet)", "Analyse complète de toutes les machines", lambda: self.scan_all_machines(mode='full'), "background-color: #2d3748; color: white;"),
            "scan_all_quick": ("⚡ Tout Analyser (Rapide)", "Analyse rapide de toutes les machines", lambda: self.scan_all_machines(mode='quick'), "background-color: #2f855a; color: white;"),
            "api": ("⚙️ Paramètres", "Configuration et clés API", self.open_api_settings, None),
            "toggle_mode": ("🔄 Mode Expert" if self.interface_mode == "simple" else "🔄 Mode Simple", 
                          "Bascule entre interface simplifiée et complète", 
                          self.toggle_interface_mode, 
                          "background-color: #805ad5; color: white;"),
        }
        
        # Ajouter les boutons de la rangée 1
        col = 0
        for btn_key in visible_buttons["row1"]:
            if btn_key in buttons_config:
                text, tooltip, callback, style = buttons_config[btn_key]
                btn = QPushButton(text)
                btn.setToolTip(tooltip)
                if style:
                    btn.setStyleSheet(style)
                btn.clicked.connect(callback)
                btn_grid.addWidget(btn, 0, col)
                col += 1
        
        # Ajouter les boutons de la rangée 2
        col = 0
        for btn_key in visible_buttons["row2"]:
            if btn_key in buttons_config:
                text, tooltip, callback, style = buttons_config[btn_key]
                btn = QPushButton(text)
                btn.setToolTip(tooltip)
                if style:
                    btn.setStyleSheet(style)
                btn.clicked.connect(callback)
                btn_grid.addWidget(btn, 1, col)
                col += 1
        
        main_layout.addWidget(btn_frame)
        
        # === BARRE D'ACTIVITÉ ===
        self.activity_frame = QFrame()
        self.activity_frame.setStyleSheet("background-color: #edf2f7; border-radius: 4px; padding: 4px;")
        activity_layout = QHBoxLayout(self.activity_frame)
        activity_layout.setContentsMargins(8, 2, 8, 2)
        
        self.activity_indicator = QProgressBar()
        self.activity_indicator.setMinimum(0)
        self.activity_indicator.setMaximum(100)
        self.activity_indicator.setValue(0)
        self.activity_indicator.setFixedHeight(14)
        self.activity_indicator.setFixedWidth(120)
        self.activity_indicator.setVisible(False)
        activity_layout.addWidget(self.activity_indicator)
        
        self.activity_label = QLabel("Prêt")
        self.activity_label.setStyleSheet("color: #4a5568; font-size: 11px;")
        activity_layout.addWidget(self.activity_label)
        activity_layout.addStretch()
        main_layout.addWidget(self.activity_frame)
        
        self.refresh_table()
        self.update_schedule_label()

    # === SCORE PANEL ===
    def on_selection_changed(self):
        machine_info = self.get_selected_machine_info()
        if not machine_info:
            self.score_display.setText("Sélectionnez une machine")
            self.score_bar.setValue(0)
            self.score_interpretation.setText("")
            return
        
        score = machine_info.get('last_score')
        hostname = machine_info.get('hostname', '?')
        
        if score is not None:
            self.score_bar.setValue(int(score))
            color = score_color(score)
            self.score_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
            if score == 0 and last_ai_error:
                self.score_display.setText(f"{hostname} — IA indisponible")
                self.score_display.setStyleSheet("font-size: 14px; font-weight: bold; color: #c53030;")
                self.score_interpretation.setText(f"Échec analyse IA. Détails:\n{last_ai_error}")
            else:
                self.score_display.setText(f"{hostname} — {score}/100 ({score_label(score)})")
                self.score_display.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {color};")
                self.score_interpretation.setText(score_description(score))
        else:
            self.score_bar.setValue(0)
            self.score_display.setText(f"{hostname} — Pas encore scanné")
            self.score_display.setStyleSheet("font-size: 14px; font-weight: bold; color: #4a5568;")
            self.score_interpretation.setText("")
        
        # Mettre à jour l'onglet Sécurité avec les données du dernier scan
        try:
            latest_scan = self.db.get_latest_scan(machine_info['id'])
            if latest_scan:
                scan_data = json.loads(latest_scan['json_data'])
                raw_data = scan_data.get('raw_data', {})
                logging.info(f"Sécurité tab: raw_data keys = {list(raw_data.keys()) if raw_data else 'VIDE'}")
                if raw_data:
                    self.security_tab.update_from_scan(raw_data)
                else:
                    logging.warning("Sécurité tab: aucune donnée raw_data (l'agent doit envoyer port_scan, integrity_check, log_analysis)")
        except Exception as e:
            logging.error(f"Erreur mise à jour onglet sécurité: {e}")

    def update_schedule_label(self):
        schedule = self.db.get_api_key("ScheduledScanTime")
        if schedule:
            self.schedule_label.setText(f"Scan auto programmé : {schedule}")
        else:
            self.schedule_label.setText("Scan auto : désactivé")

    # === ANIMATIONS ===
    def update_network_badge(self, count):
        """Met à jour le badge de l'onglet réseau."""
        try:
            tab_text = "🌐 Réseau"
            if count > 0:
                tab_text += f" ({count})"
            self.tabs.setTabText(1, tab_text)
        except Exception as e:
            logging.error(f"Erreur mise à jour badge réseau: {e}")

    def update_traffic_badge(self, count):
        """Met à jour le badge de l'onglet trafic."""
        try:
            tab_text = "📊 Trafic"
            if count > 0:
                tab_text += f" ({count})"
            self.tabs.setTabText(2, tab_text)
        except Exception as e:
            logging.error(f"Erreur mise à jour badge trafic: {e}")

    def update_animations(self):
        """Met à jour les animations de scan toutes les 500ms."""
        global scan_anim_tick
        scan_anim_tick += 1
        
        n_scanning = len(scanning_machines)
        if n_scanning > 0:
            self.activity_indicator.setVisible(True)
            if scan_progress_total > 0:
                progress = int((scan_progress_done / scan_progress_total) * 100)
                progress = max(0, min(progress, 95))
                self.activity_indicator.setValue(progress)
            dots = "." * ((scan_anim_tick % 3) + 1)
            names = []
            for ws, info in server.connected_agents.items():
                if info['id'] in scanning_machines:
                    names.append(info.get('hostname', '?'))
            if names:
                if scan_progress_total > 0:
                    self.activity_label.setText(f"Scan en cours sur {', '.join(names)} — {scan_progress_done}/{scan_progress_total}{dots}")
                else:
                    self.activity_label.setText(f"Scan en cours sur {', '.join(names)}{dots}")
            else:
                if scan_progress_total > 0:
                    self.activity_label.setText(f"Scan en cours — {scan_progress_done}/{scan_progress_total}{dots}")
                else:
                    self.activity_label.setText(f"Scan en cours{dots}")
            self.activity_label.setStyleSheet("color: #2c5282; font-size: 11px; font-weight: bold;")
            
            # Mettre à jour le statut dans le tableau
            for row in range(self.table.rowCount()):
                item = self.table.item(row, 0)
                if item:
                    machine_id = item.data(Qt.ItemDataRole.UserRole)
                    if machine_id in scanning_machines:
                        anim_frames = ["Scan en cours   ", "Scan en cours.  ", "Scan en cours.. ", "Scan en cours..."]
                        frame = anim_frames[scan_anim_tick % 4]
                        status_item = self.table.item(row, 3)
                        if status_item:
                            status_item.setText(frame)
                            color_pulse = "#2c5282" if scan_anim_tick % 2 == 0 else "#4299e1"
                            status_item.setForeground(QBrush(QColor(color_pulse)))
        else:
            self.activity_indicator.setValue(0)
            self.activity_indicator.setVisible(False)
            self.activity_label.setText("Prêt")
            self.activity_label.setStyleSheet("color: #4a5568; font-size: 11px;")

    # === ACTIONS ===
    def request_rescan(self, mode='full'):
        """Demande un nouveau scan à la machine sélectionnée.
        
        Args:
            mode: 'full' pour scan complet (~60-90s), 'quick' pour scan rapide (~15-20s)
        """
        machine_id = self.get_selected_machine_id()
        if not machine_id:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner une machine.")
            return
        
        # Déterminer le nombre d'étapes selon le mode
        total_steps = 4 if mode == 'quick' else 5
        label_prefix = "Scan rapide" if mode == 'quick' else "Scan complet"
        
        # Trouver le websocket de l'agent
        for ws, info in server.connected_agents.items():
            if info['id'] == machine_id:
                if server_loop:
                    global scan_progress_total, scan_progress_done, scan_step_total, scan_step_done, scan_step_label, last_ai_error
                    scan_progress_total = 1
                    scan_progress_done = 0
                    scan_step_total = total_steps
                    scan_step_done = 0
                    scan_step_label = f"{info['hostname']}: {label_prefix}..."
                    last_ai_error = None
                    self.activity_indicator.setValue(0)
                    self.activity_indicator.setVisible(True)
                    scanning_machines.add(machine_id)
                    asyncio.run_coroutine_threadsafe(
                        server.request_scan(ws, info, mode), server_loop
                    )
                    self.open_agent_scan_progress([info['hostname']])
                return
        
        QMessageBox.warning(self, "Erreur", "Cette machine n'est pas connectée actuellement.")

    def scan_all_machines(self, mode='full'):
        """Demande un scan à toutes les machines connectées.
        
        Args:
            mode: 'full' pour scan complet (~60-90s), 'quick' pour scan rapide (~15-20s)
        """
        if not server.connected_agents:
            QMessageBox.warning(self, "Erreur", "Aucune machine connectée.")
            return
        
        count = 0
        global scan_progress_total, scan_progress_done, scan_step_total, scan_step_done, scan_step_label, last_ai_error
        scan_progress_total = len(server.connected_agents)
        scan_progress_done = 0
        scan_step_total = 4 if mode == 'quick' else 5
        scan_step_done = 0
        scan_step_label = "Scan rapide..." if mode == 'quick' else "Scan complet..."
        last_ai_error = None
        self.activity_indicator.setValue(0)
        self.activity_indicator.setVisible(True)
        hostnames = []
        for ws, info in list(server.connected_agents.items()):
            if server_loop:
                scanning_machines.add(info['id'])
                asyncio.run_coroutine_threadsafe(
                    server.request_scan(ws, info, mode), server_loop
                )
                count += 1
                hostnames.append(info.get('hostname', '?'))
        
        if count:
            self.open_agent_scan_progress(hostnames)

    def open_agent_scan_progress(self, hostnames):
        """Ouvre une fenêtre modale de progression pour les scans agents."""
        from PyQt6.QtWidgets import QProgressDialog
        # Réinitialiser le flag de complétion
        self._scan_dialog_completed = False
        total = max(scan_progress_total, 1)
        label = f"Scan en cours sur {', '.join(hostnames)}..." if hostnames else "Scan en cours..."
        self.agent_progress_dialog = QProgressDialog(label, "Fermer", 0, total, self)
        self.agent_progress_dialog.setWindowTitle("Scan des agents")
        self.agent_progress_dialog.setMinimumDuration(0)
        self.agent_progress_dialog.setAutoClose(True)
        self.agent_progress_dialog.setAutoReset(False)
        self.agent_progress_dialog.setValue(0)
        self.agent_progress_dialog.show()
        self._agent_progress_timer = QTimer(self)
        self._agent_progress_timer.setInterval(400)
        self._agent_progress_timer.timeout.connect(self._update_agent_progress_dialog)
        self._agent_progress_timer.start()

    def _update_agent_progress_dialog(self):
        dlg = getattr(self, 'agent_progress_dialog', None)
        if dlg is None:
            return
        # Vérifier si déjà complété pour éviter les répétitions
        if getattr(self, '_scan_dialog_completed', False):
            return
        # Granularité fine: chaque machine = scan_step_total étapes IA
        steps_per_machine = max(scan_step_total or 5, 1)
        total_fine = max(scan_progress_total, 1) * steps_per_machine
        done_fine = min(scan_progress_done, max(scan_progress_total, 1)) * steps_per_machine
        # Ajouter la progression IA en cours pour la machine actuelle
        if scan_progress_done < scan_progress_total:
            done_fine += min(scan_step_done, steps_per_machine)
        done_fine = min(done_fine, total_fine)
        dlg.setMaximum(total_fine)
        dlg.setValue(done_fine)
        if scan_step_label:
            dlg.setLabelText(f"{scan_step_label} ({done_fine}/{total_fine})")
        elif scan_progress_done < scan_progress_total:
            dlg.setLabelText(f"Collecte agent en cours... ({done_fine}/{total_fine})")
        else:
            dlg.setLabelText("✅ Scan et analyse terminés.")
        if last_ai_error:
            dlg.setLabelText(f"⚠ IA indisponible:\n{last_ai_error}")
        # Scan terminé - fermer proprement
        if not scanning_machines and scan_progress_total > 0 and scan_progress_done >= scan_progress_total:
            self._scan_dialog_completed = True
            self._agent_progress_timer.stop()
            dlg.setValue(total_fine)
            # Fermer le dialog après un court délai
            QTimer.singleShot(500, dlg.close)
            if last_ai_error:
                QMessageBox.critical(self, "Erreur IA", f"L'analyse IA a échoué.\n\n{last_ai_error}\n\nVérifiez vos clés API dans Paramètres.")

    def check_emails(self):
        """Vérifie des adresses email via HaveIBeenPwned sur la machine sélectionnée."""
        machine_id = self.get_selected_machine_id()
        if not machine_id:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner une machine.")
            return
        
        api_key = self.db.get_api_key("HaveIBeenPwned")
        if not api_key or api_key.strip() == "":
            QMessageBox.warning(self, "Clé manquante", 
                "Aucune clé API HaveIBeenPwned configurée.\n"
                "Allez dans Paramètres > Clés API pour en ajouter une.\n"
                "Obtenez-la sur : https://haveibeenpwned.com/API/Key")
            return
        
        emails_str, ok = QInputDialog.getText(self, "Vérifier des Emails",
            "Entrez les adresses email à vérifier (séparées par des virgules) :")
        if not ok or not emails_str.strip():
            return
        
        emails = [e.strip() for e in emails_str.split(',') if e.strip()]
        if not emails:
            return
        
        for ws, info in server.connected_agents.items():
            if info['id'] == machine_id:
                if server_loop:
                    asyncio.run_coroutine_threadsafe(
                        server.request_email_check(ws, emails, api_key), server_loop
                    )
                    QMessageBox.information(self, "HIBP", 
                        f"Vérification de {len(emails)} email(s) lancée sur {info['hostname']}.\n"
                        "Les résultats seront visibles dans le rapport IA.")
                return
        
        QMessageBox.warning(self, "Erreur", "Cette machine n'est pas connectée.")

    def run_network_scan(self):
        from PyQt6.QtWidgets import QProgressDialog
        
        scanner = NetworkScannerFixed()
        networks = scanner.network_ranges or ["192.168.1.0/24"]
        scan_targets = []
        try:
            import ipaddress
            for network_range in networks:
                network = ipaddress.IPv4Network(network_range, strict=False)
                scan_targets.extend(str(ip) for ip in network.hosts())
        except Exception:
            scan_targets = [f"192.168.1.{i}" for i in range(1, 255)]
        total_ips = len(scan_targets)
        
        self.progress_dialog = QProgressDialog("Scan du réseau en cours...", "Annuler", 0, max(total_ips, 1), self)
        self.progress_dialog.setWindowTitle("Scanner Réseau")
        self.progress_dialog.setModal(True)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.setValue(0)
        self.scan_cancelled = False
        
        def update_progress(current, total, ip):
            QMetaObject.invokeMethod(self.progress_dialog, "setValue",
                Qt.ConnectionType.QueuedConnection, Q_ARG(int, current))
            QMetaObject.invokeMethod(self.progress_dialog, "setLabelText",
                Qt.ConnectionType.QueuedConnection,
                Q_ARG(str, f"Scan de {ip}... ({current}/{total})"))
        
        def background_scan():
            from concurrent.futures import ThreadPoolExecutor, as_completed
            devices = []
            current = 0
            
            try:
                with ThreadPoolExecutor(max_workers=80) as executor:
                    futures = {executor.submit(scanner._scan_single_ip, ip): ip for ip in scan_targets}
                    for future in as_completed(futures):
                        ip = futures[future]
                        if self.scan_cancelled:
                            break
                        current += 1
                        update_progress(current, total_ips, ip)
                        try:
                            device = future.result()
                        except Exception:
                            device = None
                        if device:
                            devices.append(device)
                            agent_id = f"unmanaged_{device['ip_address'].replace('.', '_')}"
                            hostname = device.get('hostname') or device['ip_address']
                            self.db.register_machine(agent_id, hostname, "Network Device", device['ip_address'])
                            self.db.update_machine_status(agent_id, "online")
            except Exception as e:
                logging.error(f"Erreur scan réseau: {e}")
            
            if not self.scan_cancelled:
                self.network_scan_results = devices
                QMetaObject.invokeMethod(self, "on_scan_finished",
                    Qt.ConnectionType.QueuedConnection, Q_ARG(int, len(devices)))
        
        self.progress_dialog.canceled.connect(lambda: setattr(self, 'scan_cancelled', True))
        threading.Thread(target=background_scan, daemon=True).start()
    
    @pyqtSlot(int)
    def on_scan_finished(self, count):
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        devices = getattr(self, 'network_scan_results', [])
        if hasattr(self, 'network_tab'):
            self.network_tab.last_scan_devices = self.network_tab.apply_support_status(devices)
            supported_devices = [d for d in self.network_tab.last_scan_devices if d.get('support_status') == 'pris en charge']
            self.network_tab.populate_devices_table(supported_devices)
        self.refresh_table()
        if count == 0:
            QMessageBox.warning(self, "Scan Terminé", "Aucun appareil détecté sur le réseau.")
        else:
            QMessageBox.information(self, "Scan Terminé", f"{count} appareil(s) détecté(s).")

    def open_api_settings(self):
        dialog = ApiSettingsDialog(self.db)
        if dialog.exec():
            self.update_schedule_label()

    def get_selected_machine_id(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            return None
        return self.table.item(selected_items[0].row(), 0).data(Qt.ItemDataRole.UserRole)

    def get_selected_machine_info(self):
        machine_id = self.get_selected_machine_id()
        if not machine_id: return None
        for m in self.db.get_active_machines():
            if m['id'] == machine_id: return m
        return None

    def export_pdf(self):
        from PyQt6.QtWidgets import QFileDialog
        import pdf_generator
        
        machine_info = self.get_selected_machine_info()
        if not machine_info:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner une machine.")
            return
        latest_scan = self.db.get_latest_scan(machine_info['id'])
        if not latest_scan:
            QMessageBox.information(self, "Infos", "Aucun scan disponible.")
            return
        try:
            data = json.loads(latest_scan['json_data'])
            ai_report = data.get('ai_report', {})
            if not ai_report:
                QMessageBox.warning(self, "Erreur", "Rapport IA non disponible. Vérifiez vos clés API.")
                return
            default_name = f"CyberScan_Rapport_{machine_info['hostname']}.pdf"
            filepath, _ = QFileDialog.getSaveFileName(self, "Sauvegarder le PDF", default_name, "PDF Files (*.pdf)")
            if filepath:
                pdf_generator.generate_pdf_report(machine_info, ai_report, filepath)
                QMessageBox.information(self, "Succès", f"Rapport sauvegardé :\n{filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Échec génération PDF: {e}")

    def show_details(self):
        machine_id = self.get_selected_machine_id()
        if not machine_id:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner une machine.")
            return
        latest_scan = self.db.get_latest_scan(machine_id)
        if not latest_scan:
            QMessageBox.information(self, "Infos", "Aucun scan disponible.")
            return
        try:
            data = json.loads(latest_scan['json_data'])
            ai_report = data.get('ai_report', {})
            if not ai_report:
                QMessageBox.warning(self, "Analyse IA non disponible", 
                    "Vérifiez vos clés API dans les Paramètres.")
                return
            
            detail_dialog = QDialog(self)
            detail_dialog.setWindowTitle("Rapport IA Détaillé")
            detail_dialog.resize(750, 650)
            layout = QVBoxLayout(detail_dialog)
            
            # Jauge en haut
            score = ai_report.get('score', 0)
            if isinstance(score, str):
                try: score = int(score)
                except: score = 0
            
            score_frame = QFrame()
            score_frame.setStyleSheet(f"background-color: {score_color(score)}15; border: 2px solid {score_color(score)}; border-radius: 8px; padding: 10px;")
            sf_layout = QHBoxLayout(score_frame)
            score_lbl = QLabel(f"{score}/100")
            score_lbl.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {score_color(score)};")
            sf_layout.addWidget(score_lbl)
            sf_layout.addWidget(QLabel(f"<b>{score_label(score)}</b><br>{score_description(score)}"))
            sf_layout.addStretch()
            layout.addWidget(score_frame)
            
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            
            level_translations = {'critical': 'CRITIQUE', 'high': 'ÉLEVÉ', 'medium': 'MOYEN', 'low': 'FAIBLE', 'unknown': 'INCONNU'}
            module_names = {
                'system_info': 'Système & Pare-feu', 'open_ports': 'Ports Ouverts',
                'event_logs': "Journaux d'Événements", 'local_accounts': 'Comptes Locaux',
                'network_shares': 'Partages Réseau', 'processes': 'Processus',
                'suspicious_services': 'Services Suspects', 'antivirus': 'Antivirus',
                'installed_programs': 'Programmes Installés',
                'user_activities': 'Activités Utilisateur'
            }
            
            html = ""
            summary = ai_report.get('summary', '')
            if summary:
                html += f"<p><b>Résumé :</b> {summary}</p><hr>"
            
            html += "<h3>VULNÉRABILITÉS ET RISQUES</h3>"
            for risk in ai_report.get('risks', []):
                level = str(risk.get('level', 'unknown')).lower()
                level_fr = level_translations.get(level, level.upper())
                color = {'critical': '#c53030', 'high': '#dd6b20', 'medium': '#d69e2e', 'low': '#38a169'}.get(level, '#333')
                title = risk.get('title', risk.get('description', ''))
                desc = risk.get('description', '')
                module = risk.get('module', '')
                remediation = risk.get('remediation', '')
                module_label = module_names.get(module, module)
                
                html += f"<p style='color:{color}'><b>[{level_fr}]</b>"
                if module_label:
                    html += f" <i>[{module_label}]</i>"
                html += f" {title}</p>"
                if desc and desc != title:
                    html += f"<p style='margin-left:20px'>{desc}</p>"
                if remediation:
                    html += f"<p style='margin-left:20px;color:#2b6cb0'><b>Remédiation :</b> {remediation}</p>"
            
            html += "<hr><h3>RECOMMANDATIONS</h3>"
            for rec in ai_report.get('recommendations', []):
                if isinstance(rec, dict):
                    action = rec.get('action', str(rec))
                    command = rec.get('command', '')
                    impact = rec.get('impact', '')
                    html += f"<p>• <b>{action}</b></p>"
                    if command:
                        html += f"<p style='margin-left:20px;font-family:monospace;background:#edf2f7'>{command}</p>"
                    if impact:
                        html += f"<p style='margin-left:20px;color:#718096'><i>Impact : {impact}</i></p>"
                else:
                    html += f"<p>• {rec}</p>"
            
            module_analysis = ai_report.get('module_analysis', {})
            if module_analysis:
                html += "<hr><h3>ANALYSE PAR MODULE</h3>"
                for key, text in module_analysis.items():
                    label = module_names.get(key, key)
                    html += f"<p><b>{label} :</b> {text}</p>"
            
            predictive = ai_report.get('predictive_analysis', {})
            if predictive:
                html += "<hr><h3>ANALYSE PRÉDICTIVE</h3>"
                if isinstance(predictive, dict):
                    for k, v in predictive.items():
                        if v:
                            k_label = {'attack_scenario': "Scénario d'attaque", 
                                       'correction_scenario': 'Scénario de correction',
                                       'estimated_time_to_fix': 'Temps estimé'}.get(k, k)
                            html += f"<p><b>{k_label} :</b> {v}</p>"
                else:
                    html += f"<p>{predictive}</p>"
            
            # Résultats HIBP
            email_results = data.get('email_breach_results', [])
            if email_results:
                html += "<hr><h3>VÉRIFICATION EMAILS (HaveIBeenPwned)</h3>"
                for er in email_results:
                    email = er.get('email', '?')
                    if er.get('error'):
                        html += f"<p>• <b>{email}</b> : Erreur — {er['error']}</p>"
                    elif er.get('breached'):
                        html += f"<p style='color:#c53030'>• <b>{email}</b> : COMPROMIS ({er.get('breach_count', '?')} fuites)</p>"
                        for b in er.get('breaches', []):
                            html += f"<p style='margin-left:20px'>— {b.get('name', '?')} ({b.get('date', '?')})</p>"
                    else:
                        html += f"<p style='color:#38a169'>• <b>{email}</b> : Aucune fuite détectée</p>"
            
            # Activités utilisateur
            user_activities = data.get('raw_data', {}).get('user_activities', {})
            if user_activities and not user_activities.get('error'):
                html += "<hr><h3>ACTIVITÉS UTILISATEUR</h3>"
                period = user_activities.get('collection_period', {})
                html += f"<p style='color:#718096'><i>Période : {period.get('from', '?')} → {period.get('to', '?')}</i></p>"
                
                apps = user_activities.get('apps_opened', [])
                if apps:
                    html += "<p><b>Applications lancées :</b></p><table border='1' cellpadding='4' style='border-collapse:collapse;width:100%'>"
                    html += "<tr style='background:#edf2f7'><th>Application</th><th>Date</th></tr>"
                    for app_entry in apps[:50]:
                        html += f"<tr><td>{app_entry.get('name', '?')}</td><td>{app_entry.get('first_seen', '?')}</td></tr>"
                    html += "</table>"
                
                sites = user_activities.get('websites_visited', [])
                if sites:
                    html += f"<p><b>Sites visités ({len(sites)}) :</b></p><table border='1' cellpadding='4' style='border-collapse:collapse;width:100%'>"
                    html += "<tr style='background:#edf2f7'><th>Navigateur</th><th>Site</th><th>Date</th></tr>"
                    for site in sites[:80]:
                        url = site.get('url', '?')
                        title = site.get('title', '')
                        display = title if title else (url[:60] + '...' if len(url) > 60 else url)
                        html += f"<tr><td>{site.get('browser', '?')}</td><td title='{url}'>{display}</td><td>{site.get('visited_at', '?')}</td></tr>"
                    html += "</table>"
                
                if not apps and not sites:
                    html += "<p style='color:#38a169'>Aucune activité enregistrée sur cette période.</p>"
            
            diagnostic = ai_report.get('diagnostic_expert', '')
            if diagnostic:
                html += f"<hr><h3>DIAGNOSTIC EXPERT</h3><p style='font-size:9px;color:#718096'>{diagnostic}</p>"
            
            text_edit.setHtml(html)
            layout.addWidget(text_edit)
            
            btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
            btn_box.accepted.connect(detail_dialog.accept)
            layout.addWidget(btn_box)
            detail_dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de lire le rapport: {e}")

    def refresh_current_view(self):
        current_index = self.tabs.currentIndex()
        if current_index == 0:
            self.refresh_table()
        elif current_index == 1:
            self.network_tab.refresh_devices()
        elif current_index == 2:
            self.traffic_tab.refresh_data()
        elif current_index == 3:
            self.on_selection_changed()

    def refresh_table(self):
        machines = self.db.get_all_machines()
        connected_ips = get_connected_agent_ips()
        connected_ids = get_connected_agent_ids()
        
        # Préserver la sélection
        selected_id = self.get_selected_machine_id()
        
        self.table.setRowCount(len(machines))
        
        supported_count = sum(1 for m in machines if str(m.get('id', '')) in connected_ids or normalize_ip(m.get('ip_address')) in connected_ips)
        self.count_label.setText(f"{len(machines)} machine(s) | {supported_count} prise(s) en charge | {len(machines) - supported_count} non prise(s) en charge")
        
        for row, machine in enumerate(machines):
            hostname_item = QTableWidgetItem(machine['hostname'])
            hostname_item.setData(Qt.ItemDataRole.UserRole, machine['id'])
            self.table.setItem(row, 0, hostname_item)
            
            ip_text = machine.get('ip_address') or "N/A"
            self.table.setItem(row, 1, QTableWidgetItem(ip_text))
            self.table.setItem(row, 2, QTableWidgetItem(machine['os_name']))
            
            supported = str(machine.get('id', '')) in connected_ids or normalize_ip(machine.get('ip_address')) in connected_ips
            status_display = 'Pris en charge' if supported else 'Non pris en charge'
            status_item = QTableWidgetItem(status_display)
            if supported:
                status_item.setForeground(QBrush(QColor("#38a169")))
            else:
                status_item.setForeground(QBrush(QColor("#d69e2e")))
            self.table.setItem(row, 3, status_item)
            
            # Score avec couleur
            sc = machine.get('last_score')
            if sc is not None:
                score_item = QTableWidgetItem(f"{sc}/100 ({score_label(sc)})")
                score_item.setForeground(QBrush(QColor(score_color(sc))))
                score_item.setFont(QFont("", -1, QFont.Weight.Bold))
            else:
                score_item = QTableWidgetItem("N/A")
                score_item.setForeground(QBrush(QColor("#a0aec0")))
            self.table.setItem(row, 4, score_item)
            
            self.table.setItem(row, 5, QTableWidgetItem(machine['last_seen'] or "Jamais"))
            
            # Restaurer la sélection
            if machine['id'] == selected_id:
                self.table.selectRow(row)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CyberScanAdmin()
    window.show()
    sys.exit(app.exec())
