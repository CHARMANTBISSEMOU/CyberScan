#!/usr/bin/env python3
"""
Test d'intégration des nouveaux onglets dans CyberScan
"""

import sys
import os
sys.path.append('.')

# Test des modules individuellement
def test_network_scanner():
    try:
        from network_scanner import NetworkScanner
        scanner = NetworkScanner()
        print('✅ NetworkScanner importé avec succès')
        return True
    except Exception as e:
        print(f'❌ Erreur NetworkScanner: {e}')
        return False

def test_traffic_monitor():
    try:
        from traffic_monitor_simple import TrafficMonitorSimple
        monitor = TrafficMonitorSimple()
        print('✅ TrafficMonitorSimple importé avec succès')
        return True
    except Exception as e:
        print(f'❌ Erreur TrafficMonitorSimple: {e}')
        return False

def test_database():
    try:
        from database import CyberScanDB
        db = CyberScanDB()
        print('✅ CyberScanDB importé avec succès')
        return True
    except Exception as e:
        print(f'❌ Erreur CyberScanDB: {e}')
        return False

def test_ui_components():
    try:
        from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
        from PyQt6.QtCore import QTimer
        
        # Test basique de création de widgets
        app = QApplication([])
        
        # Test NetworkTab
        from app import NetworkTab
        network_tab = NetworkTab()
        print('✅ NetworkTab créé avec succès')
        
        # Test TrafficTab
        from app import TrafficTab
        traffic_tab = TrafficTab()
        print('✅ TrafficTab créé avec succès')
        
        app.quit()
        return True
        
    except Exception as e:
        print(f'❌ Erreur UI components: {e}')
        return False

def main():
    print('=== Test d\'intégration CyberScan ===')
    
    tests = [
        ('Base de données', test_database),
        ('Scanner réseau', test_network_scanner),
        ('Moniteur trafic', test_traffic_monitor),
        ('Composants UI', test_ui_components)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f'\n🧪 Test: {test_name}')
        result = test_func()
        results.append((test_name, result))
    
    print('\n=== Résultats ===')
    success_count = 0
    for test_name, result in results:
        status = '✅ SUCCÈS' if result else '❌ ÉCHEC'
        print(f'{test_name}: {status}')
        if result:
            success_count += 1
    
    print(f'\n📊 Score: {success_count}/{len(results)} tests réussis')
    
    if success_count == len(results):
        print('🎉 Tous les tests d\'intégration réussis!')
        print('Les nouveaux onglets Réseau et Trafic sont prêts à être utilisés.')
    else:
        print('⚠️ Certains tests ont échoué. Vérifiez les erreurs ci-dessus.')

if __name__ == "__main__":
    main()
