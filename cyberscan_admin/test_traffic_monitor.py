#!/usr/bin/env python3
"""
Test du module TrafficMonitor pour CyberScan
"""

import sys
import logging
from traffic_monitor import TrafficMonitor

def main():
    # Configuration du logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    print('=== Test du module TrafficMonitor ===')
    
    try:
        # Créer une instance du moniteur
        monitor = TrafficMonitor()
        print('✓ TrafficMonitor initialisé avec succès')
        
        # Tester la surveillance
        print('🔍 Démarrage de la surveillance réseau...')
        
        def on_alert(alert):
            print(f'🚨 ALERTE: {alert["type"]} - {alert["local_ip"]} -> {alert["remote_ip"]}')
            print(f'   Protocole: {alert["protocol"]}, Processus: {alert.get("process_name", "Unknown")}')
            print(f'   Détails: {alert["details"]}')
        
        if monitor.start_monitoring(on_alert):
            print('✅ Surveillance démarrée avec succès')
            
            # Laisser tourner 30 secondes pour le test
            import time
            print('📊 Test en cours pendant 30 secondes...')
            
            for i in range(6):
                time.sleep(5)
                stats = monitor.get_statistics()
                print(f'   Cycle {i+1}: {stats.get("connections_checked", 0)} connexions vérifiées')
            
            # Afficher les connexions récentes
            connections = monitor.get_recent_connections(10)
            print(f'✓ {len(connections)} connexions récentes trouvées')
            
            for conn in connections[:3]:  # Limiter à 3 pour l'affichage
                print(f'  - {conn["protocol"]} {conn["local_ip"]}:{conn["local_port"]} -> {conn["remote_ip"]}:{conn["remote_port"]}')
                print(f'    État: {conn["state"]}, Processus: {conn.get("process_name", "Unknown")}, Risque: {conn["risk_score"]}/10')
            
            # Afficher les alertes
            alerts = monitor.get_alerts(5)
            print(f'✓ {len(alerts)} alertes trouvées')
            
            # Arrêter la surveillance
            monitor.stop_monitoring()
            print('✅ Surveillance arrêtée')
            
        else:
            print('❌ Impossible de démarrer la surveillance')
        
        print('✅ Test terminé avec succès!')
        
    except Exception as e:
        print(f'❌ Erreur: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
