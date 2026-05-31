#!/usr/bin/env python3
"""
CyberScan - Application de Sécurité Réseau
Lanceur principal pour l'interface complète avec scan réseau et surveillance trafic.
"""

import sys
import os
import logging
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# Ajouter le répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyberscan.log'),
        logging.StreamHandler()
    ]
)

def main():
    """Point d'entrée principal de CyberScan."""
    print("🚀 Lancement de CyberScan...")
    print("=" * 60)
    
    try:
        # Créer l'application Qt
        app = QApplication(sys.argv)
        app.setApplicationName("CyberScan")
        app.setApplicationVersion("2.0")
        app.setOrganizationName("CyberScan Security")
        
        # Configuration du style
        app.setStyle("Fusion")
        
        # Configuration des polices
        font = QFont("Segoe UI", 10)
        app.setFont(font)
        
        # Importer et créer l'interface principale
        from app import CyberScanAdmin
        
        print("📦 Initialisation de l'interface...")
        window = CyberScanAdmin()
        
        # Afficher la fenêtre
        window.show()
        window.raise_()
        window.activateWindow()
        
        print("✅ CyberScan démarré avec succès!")
        print("🌐 Fonctionnalités disponibles:")
        print("   • 🖥️ Machines: Gestion des agents et scans")
        print("   • 🌐 Réseau: Scan automatique et découverte d'appareils")
        print("   • 📊 Trafic: Surveillance des connexions en temps réel")
        print("=" * 60)
        print("📊 Logs enregistrés dans: cyberscan.log")
        print("🔍 Base de données: cyberscan.db")
        print("=" * 60)
        
        # Démarrer la boucle d'événements
        sys.exit(app.exec())
        
    except ImportError as e:
        error_msg = f"Erreur d'importation: {e}\n\n"
        error_msg += "Veuillez installer les dépendances requises:\n"
        error_msg += "pip install PyQt6 psutil websockets groq anthropic zeroconf"
        
        print(f"❌ {error_msg}")
        QMessageBox.critical(None, "Erreur de dépendances", error_msg)
        sys.exit(1)
        
    except Exception as e:
        error_msg = f"Erreur lors du démarrage de CyberScan:\n{e}"
        
        print(f"❌ {error_msg}")
        logging.exception("Erreur critique au démarrage")
        
        QMessageBox.critical(None, "Erreur de démarrage", error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()
