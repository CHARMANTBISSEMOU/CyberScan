#!/usr/bin/env python3
"""
Diagnostic du scan réseau dans l'interface admin CyberScan
Identifie les blocages et problèmes de scan.
"""

import sys
import os
import logging
from PyQt6.QtWidgets import QApplication
from app import CyberScanAdmin
from network_scanner_fixed import NetworkScannerFixed
import time

# Configuration du logging détaillé
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_scanner_directly():
    """Test le scanner réseau directement."""
    print("=" * 60)
    print("🔍 TEST DIRECT DU SCANNER RÉSEAU")
    print("=" * 60)
    
    try:
        scanner = NetworkScannerFixed()
        print(f"✅ Scanner créé: {type(scanner).__name__}")
        print(f"✅ Réseaux détectés: {scanner.network_ranges}")
        
        # Test de scan manuel
        print("\n🔍 Lancement scan manuel...")
        start_time = time.time()
        
        devices = scanner.manual_scan()
        
        end_time = time.time()
        print(f"✅ Scan terminé en {end_time - start_time:.2f} secondes")
        print(f"✅ Appareils découverts: {len(devices)}")
        
        for i, device in enumerate(devices):
            print(f"  📱 Appareil {i+1}: {device['ip_address']} - {device.get('hostname', 'Unknown')}")
        
        # Test des fonctions utilisées par l'interface
        print("\n🔍 Test des fonctions interface...")
        
        discovered = scanner.get_discovered_devices()
        print(f"✅ get_discovered_devices(): {len(discovered)} appareils")
        
        events = scanner.get_recent_events(10)
        print(f"✅ get_recent_events(): {len(events)} événements")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur scanner direct: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_interface_components():
    """Test les composants de l'interface."""
    print("\n" + "=" * 60)
    print("🖥️ TEST DES COMPOSANTS DE L'INTERFACE")
    print("=" * 60)
    
    try:
        app = QApplication(sys.argv)
        window = CyberScanAdmin()
        
        print(f"✅ Fenêtre principale créée")
        print(f"✅ Nombre d'onglets: {window.tabs.count()}")
        
        # Test de l'onglet réseau
        network_tab = window.network_tab
        print(f"✅ Onglet réseau: {type(network_tab).__name__}")
        
        # Test du scanner dans l'onglet
        scanner = network_tab.network_scanner
        print(f"✅ Scanner dans onglet: {type(scanner).__name__}")
        print(f"✅ Réseaux dans onglet: {scanner.network_ranges}")
        
        # Test des boutons
        start_btn = network_tab.start_btn
        stop_btn = network_tab.stop_btn
        refresh_btn = network_tab.refresh_btn
        
        print(f"✅ Bouton démarrer: {start_btn.isEnabled()}")
        print(f"✅ Bouton arrêter: {stop_btn.isEnabled()}")
        print(f"✅ Bouton rafraîchir: {refresh_btn.isEnabled()}")
        
        # Test de refresh_devices
        print("\n🔄 Test de refresh_devices...")
        try:
            network_tab.refresh_devices()
            print("✅ refresh_devices() exécuté sans erreur")
        except Exception as e:
            print(f"❌ Erreur refresh_devices(): {e}")
            import traceback
            traceback.print_exc()
        
        # Test de start_monitoring
        print("\n▶️ Test de start_monitoring...")
        try:
            # Simuler le clic sans bloquer
            network_tab.start_monitoring()
            print("✅ start_monitoring() exécuté")
            
            # Attendre un peu pour voir si le scan démarre
            time.sleep(2)
            
            # Vérifier les appareils découverts
            devices = scanner.get_discovered_devices()
            print(f"✅ Appareils après démarrage: {len(devices)}")
            
            # Arrêter la surveillance
            network_tab.stop_monitoring()
            print("✅ Surveillance arrêtée")
            
        except Exception as e:
            print(f"❌ Erreur start_monitoring(): {e}")
            import traceback
            traceback.print_exc()
        
        app.quit()
        return True
        
    except Exception as e:
        print(f"❌ Erreur interface: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_database_connection():
    """Test la connexion à la base de données."""
    print("\n" + "=" * 60)
    print("🗄️ TEST DE LA BASE DE DONNÉES")
    print("=" * 60)
    
    try:
        import sqlite3
        
        db_path = "cyberscan.db"
        print(f"📂 Base de données: {db_path}")
        
        if os.path.exists(db_path):
            print(f"✅ Fichier de base de données existe")
            size = os.path.getsize(db_path)
            print(f"✅ Taille: {size:,} octets")
        else:
            print(f"⚠️ Base de données non trouvée, création...")
        
        # Test de connexion
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Vérifier les tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"✅ Tables trouvées: {[t[0] for t in tables]}")
        
        # Vérifier la table network_devices
        cursor.execute("SELECT COUNT(*) FROM network_devices;")
        device_count = cursor.fetchone()[0]
        print(f"✅ Appareils en base: {device_count}")
        
        # Vérifier la table network_events
        cursor.execute("SELECT COUNT(*) FROM network_events;")
        event_count = cursor.fetchone()[0]
        print(f"✅ Événements en base: {event_count}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Erreur base de données: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Fonction principale de diagnostic."""
    print("🔍 DIAGNOSTIC COMPLET DU SCAN RÉSEAU CYBERSCAN")
    print("=" * 60)
    
    tests = [
        ("Base de données", test_database_connection),
        ("Scanner direct", test_scanner_directly),
        ("Interface admin", test_interface_components),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n🧪 Exécution du test: {test_name}")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ Erreur critique dans {test_name}: {e}")
            results[test_name] = False
    
    # Résumé
    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ DU DIAGNOSTIC")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ OK" if result else "❌ ÉCHEC"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n📈 Score: {passed}/{total} tests réussis")
    
    if passed == total:
        print("🎉 Tous les tests sont OK! Le scan devrait fonctionner.")
    elif passed >= total // 2:
        print("⚠️ Certains tests ont échoué. Problème identifié.")
    else:
        print("❌ Plusieurs tests ont échoué. Problèmes majeurs.")
    
    # Recommandations
    print("\n💡 RECOMMANDATIONS:")
    
    if not results.get("Base de données"):
        print("- Vérifiez les permissions d'écriture")
        print("- Assurez-vous que SQLite est accessible")
    
    if not results.get("Scanner direct"):
        print("- Vérifiez la configuration réseau")
        print("- Testez les permissions administratives")
    
    if not results.get("Interface admin"):
        print("- Vérifiez l'initialisation de PyQt6")
        print("- Testez la connexion entre composants")

if __name__ == "__main__":
    main()
