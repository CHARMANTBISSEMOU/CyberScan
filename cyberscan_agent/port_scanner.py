"""
CyberScan - Module Port Scanner (nmap-style)
Scan de ports TCP avec détection de services et bannières.
"""

import socket
import subprocess
import concurrent.futures
import logging
import struct
import time
from datetime import datetime

NO_WINDOW = subprocess.CREATE_NO_WINDOW

# Ports critiques à scanner (top 100 les plus courants)
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPCBind', 135: 'MSRPC', 137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP',
    162: 'SNMP-Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 515: 'LPD', 587: 'SMTP-Submission', 631: 'IPP',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1025: 'NFS', 1080: 'SOCKS',
    1433: 'MSSQL', 1434: 'MSSQL-UDP', 1521: 'Oracle', 1723: 'PPTP',
    2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL', 2181: 'ZooKeeper',
    3306: 'MySQL', 3389: 'RDP', 3690: 'SVN', 4333: 'mSQL',
    4443: 'Pharos', 4444: 'Metasploit', 5000: 'UPnP', 5432: 'PostgreSQL',
    5555: 'Android-ADB', 5900: 'VNC', 5901: 'VNC-1', 5985: 'WinRM',
    5986: 'WinRM-SSL', 6379: 'Redis', 6666: 'IRC', 7001: 'WebLogic',
    8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt2', 9090: 'WebSM', 9200: 'Elasticsearch',
    9418: 'Git', 10000: 'Webmin', 27017: 'MongoDB', 27018: 'MongoDB-Alt',
    50000: 'SAP', 50070: 'Hadoop'
}

# Ports dangereux (risque élevé si ouverts)
DANGEROUS_PORTS = {
    21, 23, 135, 137, 138, 139, 445, 514, 1080, 1434,
    3389, 4444, 5555, 5900, 6666, 27017
}

# Ports critiques pour la sécurité
SECURITY_PORTS = {
    22, 443, 465, 587, 636, 993, 995, 5986
}


def scan_port(host, port, timeout=1.5):
    """Scanne un port TCP et tente de récupérer la bannière."""
    result = {
        'port': port,
        'state': 'closed',
        'service': COMMON_PORTS.get(port, 'unknown'),
        'banner': '',
        'risk': 'low'
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        conn_result = sock.connect_ex((host, port))
        
        if conn_result == 0:
            result['state'] = 'open'
            
            # Évaluer le risque
            if port in DANGEROUS_PORTS:
                result['risk'] = 'high'
            elif port in SECURITY_PORTS:
                result['risk'] = 'low'
            elif port > 1024:
                result['risk'] = 'medium'
            
            # Tenter de récupérer la bannière
            try:
                sock.settimeout(2)
                # Envoyer une requête selon le service
                if port in (80, 8080, 8000, 8443, 443):
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                elif port == 22:
                    pass  # SSH envoie sa bannière automatiquement
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    result['banner'] = banner[:200]  # Limiter à 200 chars
            except:
                pass
        
        sock.close()
        
    except socket.timeout:
        result['state'] = 'filtered'
    except Exception:
        pass
    
    return result


def scan_host_ports(host='127.0.0.1', ports=None, max_workers=50, timeout=1.5):
    """Scan complet des ports d'un hôte avec multithreading."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    open_ports = []
    filtered_ports = []
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result['state'] == 'open':
                    open_ports.append(result)
                elif result['state'] == 'filtered':
                    filtered_ports.append(result)
            except Exception:
                pass
    
    scan_duration = time.time() - start_time
    
    # Trier par numéro de port
    open_ports.sort(key=lambda x: x['port'])
    filtered_ports.sort(key=lambda x: x['port'])
    
    # Évaluation du risque global
    high_risk_count = sum(1 for p in open_ports if p['risk'] == 'high')
    medium_risk_count = sum(1 for p in open_ports if p['risk'] == 'medium')
    
    if high_risk_count >= 3:
        risk_level = 'critical'
    elif high_risk_count >= 1:
        risk_level = 'high'
    elif medium_risk_count >= 5:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'host': host,
        'scan_time': datetime.now().isoformat(),
        'duration_seconds': round(scan_duration, 2),
        'total_ports_scanned': len(ports),
        'open_ports': open_ports,
        'open_count': len(open_ports),
        'filtered_ports': filtered_ports[:10],  # Limiter
        'filtered_count': len(filtered_ports),
        'risk_level': risk_level,
        'high_risk_ports': [p['port'] for p in open_ports if p['risk'] == 'high'],
        'recommendations': generate_recommendations(open_ports)
    }


def generate_recommendations(open_ports):
    """Génère des recommandations basées sur les ports ouverts."""
    recommendations = []
    
    port_numbers = {p['port'] for p in open_ports}
    
    if 23 in port_numbers:
        recommendations.append("CRITIQUE: Telnet (23) ouvert - Protocole non chiffré, désactivez-le et utilisez SSH")
    if 21 in port_numbers:
        recommendations.append("ÉLEVÉ: FTP (21) ouvert - Utilisez SFTP/FTPS à la place")
    if 3389 in port_numbers:
        recommendations.append("ÉLEVÉ: RDP (3389) ouvert - Restreignez l'accès par VPN ou IP whitelist")
    if 445 in port_numbers:
        recommendations.append("ÉLEVÉ: SMB (445) ouvert - Vérifiez le partage réseau, risque de ransomware")
    if 135 in port_numbers or 139 in port_numbers:
        recommendations.append("MOYEN: Ports NetBIOS/RPC ouverts - Désactivez si non nécessaire")
    if 5900 in port_numbers:
        recommendations.append("ÉLEVÉ: VNC (5900) ouvert - Utilisez un tunnel SSH ou VPN")
    if 27017 in port_numbers:
        recommendations.append("CRITIQUE: MongoDB (27017) ouvert - Base de données exposée sans auth")
    if 6379 in port_numbers:
        recommendations.append("CRITIQUE: Redis (6379) ouvert - Configurez l'authentification")
    if 4444 in port_numbers:
        recommendations.append("CRITIQUE: Port 4444 (Metasploit) ouvert - Possible backdoor!")
    if 5555 in port_numbers:
        recommendations.append("ÉLEVÉ: ADB (5555) ouvert - Accès Android non sécurisé")
    if 1080 in port_numbers:
        recommendations.append("MOYEN: SOCKS Proxy (1080) ouvert - Peut être exploité pour le pivoting")
    
    if not recommendations:
        if len(open_ports) <= 5:
            recommendations.append("BON: Peu de ports ouverts, surface d'attaque réduite")
        else:
            recommendations.append(f"ATTENTION: {len(open_ports)} ports ouverts - Vérifiez la nécessité de chacun")
    
    return recommendations


# Ports critiques uniquement pour scan rapide (top 20)
CRITICAL_PORTS_QUICK = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 135: 'MSRPC', 139: 'NetBIOS-SSN', 443: 'HTTPS', 445: 'SMB',
    1433: 'MSSQL', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
    5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 27017: 'MongoDB',
    4444: 'Metasploit', 5555: 'ADB'
}


def run_port_scan():
    """Fonction principale appelée par win_scanner (mode complet - 50 ports)."""
    return scan_host_ports(host='127.0.0.1')


def run_port_scan_quick():
    """Mode rapide: scan seulement les 20 ports critiques (< 10s)."""
    return scan_host_ports(
        host='127.0.0.1',
        ports=list(CRITICAL_PORTS_QUICK.keys()),
        max_workers=20,
        timeout=1.0
    )


if __name__ == "__main__":
    import json
    result = run_port_scan()
    print(json.dumps(result, indent=2))
