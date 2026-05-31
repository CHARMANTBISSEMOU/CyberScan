#!/usr/bin/env python3
"""
Diagnostic du scan réseau CyberScan
Identifie les problèmes et fournit des solutions.
"""

import socket
import subprocess
import platform
import ipaddress
import psutil
import logging
import time
from concurrent.futures import ThreadPoolExecutor

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_network_interfaces():
    """Test des interfaces réseau."""
    print("=== TEST DES INTERFACES RÉSEAU ===")
    
    try:
        interfaces = psutil.net_if_addrs()
        print(f"✅ {len(interfaces)} interfaces réseau détectées:")
        
        for name, addresses in interfaces.items():
            print(f"  📡 {name}:")
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    print(f"    IPv4: {addr.address}")
                    if addr.netmask:
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        print(f"    Réseau: {network}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur interfaces réseau: {e}")
        return False

def test_ping_functionality():
    """Test la fonctionnalité ping."""
    print("\n=== TEST DE CONNECTIVITÉ PING ===")
    
    # IPs de test
    test_ips = [
        "127.0.0.1",  # Localhost
        "8.8.8.8",    # Google DNS
        "1.1.1.1"     # Cloudflare DNS
    ]
    
    for ip in test_ips:
        try:
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '0.5', ip]
            
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            if result.returncode == 0:
                print(f"✅ Ping {ip}: OK")
            else:
                print(f"❌ Ping {ip}: Échec")
        except Exception as e:
            print(f"❌ Ping {ip}: Erreur {e}")

def test_arp_functionality():
    """Test la fonctionnalité ARP."""
    print("\n=== TEST DE LA TABLE ARP ===")
    
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            arp_entries = [line for line in lines if line.strip()]
            print(f"✅ Table ARP accessible ({len(arp_entries)} entrées)")
            
            # Afficher quelques entrées
            for i, line in enumerate(arp_entries[:3]):
                print(f"  📋 {line.strip()}")
            
            return True
        else:
            print(f"❌ Erreur ARP: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Erreur test ARP: {e}")
        return False

def test_port_scanning():
    """Test la fonctionnalité de scan de ports."""
    print("\n=== TEST DE SCAN DE PORTS ===")
    
    # Test sur localhost avec ports communs
    test_ip = "127.0.0.1"
    test_ports = [22, 80, 443, 3389, 5432]
    
    def scan_port(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    print(f"🔍 Scan des ports sur {test_ip}:")
    open_ports = []
    
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(scan_port, test_ip, port): port for port in test_ports}
            for future in futures:
                port = future.result()
                if port:
                    open_ports.append(port)
                    print(f"  ✅ Port {port} ouvert")
                else:
                    print(f"  ❌ Port {futures[future]} fermé")
        
        print(f"📊 Résultat: {len(open_ports)} ports ouverts")
        return True
    except Exception as e:
        print(f"❌ Erreur scan ports: {e}")
        return False

def test_dns_resolution():
    """Test la résolution DNS."""
    print("\n=== TEST DE RÉSOLUTION DNS ===")
    
    test_hosts = [
        "localhost",
        "google.com",
        "github.com"
    ]
    
    for host in test_hosts:
        try:
            ip = socket.gethostbyname(host)
            print(f"✅ {host} → {ip}")
        except Exception as e:
            print(f"❌ {host}: Erreur {e}")

def test_network_range_detection():
    """Test la détection de plage réseau."""
    print("\n=== TEST DE DÉTECTION DE PLAGE RÉSEAU ===")
    
    try:
        interfaces = psutil.net_if_addrs()
        network_ranges = []
        
        for interface_name, addresses in interfaces.items():
            for addr in addresses:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    try:
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        if network.is_private:
                            network_ranges.append(str(network))
                            print(f"🌐 Réseau détecté: {network} (interface: {interface_name})")
                    except:
                        continue
        
        if not network_ranges:
            print("⚠️ Aucun réseau privé détecté, utilisation du réseau par défaut")
            network_ranges = ["192.168.1.0/24"]
        
        print(f"📊 Total: {len(network_ranges)} plages réseau")
        return network_ranges
    except Exception as e:
        print(f"❌ Erreur détection réseau: {e}")
        return ["192.168.1.0/24"]

def test_quick_scan():
    """Test un scan rapide sur une petite plage."""
    print("\n=== TEST DE SCAN RAPIDE ===")
    
    # Utiliser une petite plage pour le test
    test_network = "192.168.1.0/30"  # 192.168.1.1 à 192.168.1.2
    
    def ping_host(ip):
        try:
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', '-w', '500', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '0.5', ip]
            
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    try:
        network = ipaddress.IPv4Network(test_network)
        ips = [str(ip) for ip in network.hosts()]
        
        print(f"🔍 Test de scan sur {test_network} ({len(ips)} IPs):")
        
        responsive_hosts = []
        for ip in ips:
            if ping_host(ip):
                responsive_hosts.append(ip)
                print(f"  ✅ {ip}: répond")
            else:
                print(f"  ❌ {ip}: ne répond pas")
        
        print(f"📊 Résultat: {len(responsive_hosts)}/{len(ips)} hôtes répondent")
        return len(responsive_hosts) > 0
    except Exception as e:
        print(f"❌ Erreur scan rapide: {e}")
        return False

def check_permissions():
    """Vérifie les permissions nécessaires."""
    print("\n=== VÉRIFICATION DES PERMISSIONS ===")
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        print(f"🔐 Droits administratifs: {'✅ Oui' if is_admin else '⚠️ Non'}")
        
        if not is_admin:
            print("💡 Certaines fonctionnalités peuvent nécessiter des droits admin:")
            print("   - Scan de ports sur certaines plages")
            print(" - Accès à la table ARP complète")
            print("   - Informations réseau détaillées")
        
        return is_admin
    except:
        print("⚠️ Impossible de vérifier les droits administratifs")
        return False

def main():
    """Fonction principale de diagnostic."""
    print("🔍 DIAGNOSTIC DU SCAN RÉSEAU CYBERSCAN")
    print("=" * 60)
    
    tests = [
        ("Interfaces réseau", test_network_interfaces),
        ("Connectivité ping", test_ping_functionality),
        ("Table ARP", test_arp_functionality),
        ("Scan de ports", test_port_scanning),
        ("Résolution DNS", test_dns_resolution),
        ("Détection réseau", test_network_range_detection),
        ("Scan rapide", test_quick_scan),
        ("Permissions", check_permissions)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
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
        print("🎉 Tous les tests sont OK! Le scan réseau devrait fonctionner.")
    elif passed >= total // 2:
        print("⚠️ Certains tests ont échoué. Le scan réseau peut avoir des problèmes.")
    else:
        print("❌ Plusieurs tests ont échoué. Le scan réseau a probablement des problèmes majeurs.")
    
    # Recommandations
    print("\n💡 RECOMMANDATIONS:")
    
    if not results.get("Interfaces réseau"):
        print("- Vérifiez que les pilotes réseau sont installés")
    
    if not results.get("Connectivité ping"):
        print("- Vérifiez votre connexion internet/réseau")
        print("- Vérifiez le firewall Windows")
    
    if not results.get("Table ARP"):
        print("- Exécutez en tant qu'administrateur")
    
    if not results.get("Scan de ports"):
        print("- Vérifiez que le firewall ne bloque pas les scans")
        print("- Exécutez en tant qu'administrateur")
    
    if not results.get("Permissions"):
        print("- Exécutez CyberScan en tant qu'administrateur pour des fonctionnalités complètes")

if __name__ == "__main__":
    main()
