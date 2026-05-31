#!/usr/bin/env python3
"""
Test du module NetworkScanner pour CyberScan
"""

import sys
import logging
from network_scanner import NetworkScanner

def main():
    # Configuration du logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    print('=== Test du module NetworkScanner ===')
    
    try:
        # Créer une instance du scanner
        scanner = NetworkScanner()
        print('✓ NetworkScanner initialisé avec succès')
        
        # Tester la détection des réseaux
        print(f'✓ Réseaux détectés: {scanner.network_ranges}')
        
        # Tester un scan rapide
        print('🔍 Lancement d\'un scan rapide...')
        scanner._quick_scan_network()
        
        # Afficher les résultats
        devices = scanner.get_devices()
        print(f'✓ {len(devices)} appareils détectés')
        
        for device in devices[:3]:  # Limiter à 3 pour le test
            ip = device.get('ip_address', 'N/A')
            hostname = device.get('hostname', 'Unknown')
            device_type = device.get('device_type', 'unknown')
            print(f'  - {ip} ({hostname}) - {device_type}')
        
        # Tester les événements
        events = scanner.get_recent_events(5)
        print(f'✓ {len(events)} événements récents')
        
        print('✅ Test terminé avec succès!')
        
    except Exception as e:
        print(f'❌ Erreur: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
