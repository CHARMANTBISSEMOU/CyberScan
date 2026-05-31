"""
CyberScan - Module Log Analyzer (logcheck/Snort-style)
Analyse les Event Logs Windows pour détecter des activités suspectes.
Détection d'intrusion basée sur les journaux système.
"""

import subprocess
import logging
import json
import re
from datetime import datetime, timedelta
from collections import Counter

NO_WINDOW = subprocess.CREATE_NO_WINDOW

# Règles de détection (inspirées Snort/OSSEC)
DETECTION_RULES = {
    'brute_force': {
        'description': 'Tentatives de force brute détectées',
        'event_ids': [4625],  # Échec de connexion
        'threshold': 5,  # 5 échecs = alerte
        'severity': 'high',
        'timewindow_minutes': 10
    },
    'privilege_escalation': {
        'description': 'Élévation de privilèges suspecte',
        'event_ids': [4672, 4673],  # Privilèges spéciaux, opération privilégiée
        'threshold': 10,
        'severity': 'medium',
        'timewindow_minutes': 5
    },
    'account_manipulation': {
        'description': 'Manipulation de comptes utilisateurs',
        'event_ids': [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740],
        'threshold': 1,
        'severity': 'high',
        'timewindow_minutes': 60
    },
    'policy_change': {
        'description': 'Modification de stratégie de sécurité',
        'event_ids': [4719, 4739, 4907],
        'threshold': 1,
        'severity': 'medium',
        'timewindow_minutes': 60
    },
    'service_manipulation': {
        'description': 'Installation/modification de services',
        'event_ids': [7045, 4697],
        'threshold': 1,
        'severity': 'high',
        'timewindow_minutes': 60
    },
    'logon_anomaly': {
        'description': 'Connexion inhabituelle (hors heures / compte système)',
        'event_ids': [4624],
        'threshold': 1,
        'severity': 'low',
        'timewindow_minutes': 60
    },
    'firewall_change': {
        'description': 'Modification des règles de pare-feu',
        'event_ids': [2004, 2005, 2006],
        'threshold': 1,
        'severity': 'high',
        'timewindow_minutes': 60
    },
    'audit_log_cleared': {
        'description': 'Journal d\'audit effacé (tentative de dissimulation)',
        'event_ids': [1102, 104],
        'threshold': 1,
        'severity': 'critical',
        'timewindow_minutes': 1440  # 24h
    },
    'powershell_suspicious': {
        'description': 'Exécution PowerShell suspecte',
        'event_ids': [4104],  # Script block logging
        'threshold': 3,
        'severity': 'medium',
        'timewindow_minutes': 10
    },
    'rdp_connection': {
        'description': 'Connexion RDP détectée',
        'event_ids': [4624],  # Type 10 = RDP
        'threshold': 1,
        'severity': 'medium',
        'timewindow_minutes': 60
    }
}

# Mots-clés suspects dans les commandes PowerShell
SUSPICIOUS_KEYWORDS = [
    'Invoke-Expression', 'IEX', 'DownloadString', 'DownloadFile',
    'Net.WebClient', 'Start-Process', 'bypass', 'hidden',
    'EncodedCommand', 'FromBase64String', 'Invoke-Mimikatz',
    'Invoke-WebRequest', 'certutil', '-urlcache', 'bitsadmin'
]


def query_event_log_powershell(log_name, event_ids, hours_back=24, max_events=500):
    """Requête les Event Logs via PowerShell (plus fiable que win32evtlog)."""
    try:
        # Construire le filtre XPath
        ids_filter = ' or '.join([f'EventID={eid}' for eid in event_ids])
        
        time_diff = hours_back * 3600 * 1000  # millisecondes
        
        ps_command = f"""
        $events = @()
        try {{
            $filter = @{{
                LogName = '{log_name}'
                StartTime = (Get-Date).AddHours(-{hours_back})
            }}
            $rawEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents {max_events} -ErrorAction SilentlyContinue | Where-Object {{ {' -or '.join([f'$_.Id -eq {eid}' for eid in event_ids])} }}
            foreach ($evt in $rawEvents) {{
                $events += @{{
                    'id' = $evt.Id
                    'time' = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    'message' = $evt.Message.Substring(0, [Math]::Min(300, $evt.Message.Length))
                    'level' = $evt.LevelDisplayName
                }}
            }}
        }} catch {{}}
        $events | ConvertTo-Json -Depth 2
        """
        
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_command],
            capture_output=True, text=True, timeout=30,
            creationflags=NO_WINDOW
        )
        
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                return [data]
            return data if data else []
        return []
        
    except subprocess.TimeoutExpired:
        return []
    except json.JSONDecodeError:
        return []
    except Exception as e:
        logging.error(f"Erreur requête Event Log {log_name}: {e}")
        return []


def analyze_failed_logins(events):
    """Analyse les tentatives de connexion échouées pour détecter le brute force."""
    if not events:
        return {'detected': False, 'details': []}
    
    # Grouper par fenêtre de temps
    source_ips = Counter()
    usernames = Counter()
    
    for evt in events:
        msg = evt.get('message', '')
        # Extraire l'IP source
        ip_match = re.search(r'Adresse.+?:\s*(\d+\.\d+\.\d+\.\d+)', msg)
        if not ip_match:
            ip_match = re.search(r'Source.+?Address:\s*(\d+\.\d+\.\d+\.\d+)', msg)
        if ip_match:
            source_ips[ip_match.group(1)] += 1
        
        # Extraire le nom d'utilisateur
        user_match = re.search(r'Nom du compte\s*:\s*(\S+)', msg)
        if not user_match:
            user_match = re.search(r'Account Name:\s*(\S+)', msg)
        if user_match:
            usernames[user_match.group(1)] += 1
    
    details = []
    detected = False
    
    for ip, count in source_ips.most_common(5):
        if count >= 5:
            detected = True
            details.append(f"IP {ip}: {count} tentatives échouées")
    
    for user, count in usernames.most_common(5):
        if count >= 3 and user not in ('-', 'SYSTEM', '$'):
            details.append(f"Compte '{user}': {count} échecs")
    
    return {'detected': detected, 'count': len(events), 'details': details}


def analyze_powershell_logs(events):
    """Détecte les commandes PowerShell suspectes."""
    suspicious = []
    
    for evt in events:
        msg = evt.get('message', '')
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in msg.lower():
                suspicious.append({
                    'time': evt.get('time', 'unknown'),
                    'keyword': keyword,
                    'snippet': msg[:150]
                })
                break
    
    return suspicious


def get_recent_logins(hours_back=24):
    """Récupère les connexions récentes et identifie les anomalies."""
    try:
        ps_command = f"""
        $logins = @()
        try {{
            $events = Get-WinEvent -FilterHashtable @{{
                LogName = 'Security'
                Id = 4624
                StartTime = (Get-Date).AddHours(-{hours_back})
            }} -MaxEvents 100 -ErrorAction SilentlyContinue
            foreach ($evt in $events) {{
                $xml = [xml]$evt.ToXml()
                $data = $xml.Event.EventData.Data
                $logonType = ($data | Where-Object Name -eq 'LogonType').'#text'
                $user = ($data | Where-Object Name -eq 'TargetUserName').'#text'
                $ip = ($data | Where-Object Name -eq 'IpAddress').'#text'
                if ($user -and $user -ne 'SYSTEM' -and $user -notlike '*$') {{
                    $logins += @{{
                        'time' = $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        'user' = $user
                        'type' = $logonType
                        'source_ip' = $ip
                    }}
                }}
            }}
        }} catch {{}}
        $logins | ConvertTo-Json -Depth 2
        """
        
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_command],
            capture_output=True, text=True, timeout=30,
            creationflags=NO_WINDOW
        )
        
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                return [data]
            return data if data else []
        return []
    except:
        return []


def run_log_analysis():
    """Exécute l'analyse complète des logs système."""
    results = {
        'scan_time': datetime.now().isoformat(),
        'alerts': [],
        'summary': {
            'total_alerts': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'failed_logins': {},
        'recent_logins': [],
        'suspicious_powershell': [],
        'risk_level': 'low',
        'recommendations': []
    }
    
    # 1. Analyser les échecs de connexion (brute force)
    failed_login_events = query_event_log_powershell('Security', [4625], hours_back=1)
    brute_force = analyze_failed_logins(failed_login_events)
    results['failed_logins'] = brute_force
    
    if brute_force['detected']:
        results['alerts'].append({
            'rule': 'brute_force',
            'severity': 'high',
            'description': 'Tentatives de force brute détectées',
            'details': brute_force['details']
        })
    
    # 2. Vérifier les manipulations de comptes
    account_events = query_event_log_powershell('Security', [4720, 4722, 4726, 4738, 4740], hours_back=24)
    if account_events:
        results['alerts'].append({
            'rule': 'account_manipulation',
            'severity': 'high',
            'description': f"{len(account_events)} manipulation(s) de comptes détectée(s)",
            'details': [e.get('message', '')[:100] for e in account_events[:3]]
        })
    
    # 3. Vérifier les installations de services
    service_events = query_event_log_powershell('System', [7045], hours_back=24)
    if service_events:
        results['alerts'].append({
            'rule': 'service_manipulation',
            'severity': 'medium',
            'description': f"{len(service_events)} nouveau(x) service(s) installé(s)",
            'details': [e.get('message', '')[:100] for e in service_events[:3]]
        })
    
    # 4. Vérifier si les logs ont été effacés
    cleared_events = query_event_log_powershell('Security', [1102], hours_back=168)  # 7 jours
    if cleared_events:
        results['alerts'].append({
            'rule': 'audit_log_cleared',
            'severity': 'critical',
            'description': 'Journal de sécurité effacé - Possible tentative de dissimulation',
            'details': [e.get('time', 'unknown') for e in cleared_events]
        })
    
    # 5. Analyser PowerShell
    ps_events = query_event_log_powershell('Microsoft-Windows-PowerShell/Operational', [4104], hours_back=6)
    suspicious_ps = analyze_powershell_logs(ps_events)
    results['suspicious_powershell'] = suspicious_ps[:10]
    
    if len(suspicious_ps) >= 3:
        results['alerts'].append({
            'rule': 'powershell_suspicious',
            'severity': 'high',
            'description': f"{len(suspicious_ps)} commande(s) PowerShell suspecte(s)",
            'details': [s['keyword'] for s in suspicious_ps[:5]]
        })
    
    # 6. Connexions récentes
    results['recent_logins'] = get_recent_logins(hours_back=24)[:20]
    
    # Vérifier connexions RDP
    rdp_logins = [l for l in results['recent_logins'] if l.get('type') == '10']
    if rdp_logins:
        results['alerts'].append({
            'rule': 'rdp_connection',
            'severity': 'medium',
            'description': f"{len(rdp_logins)} connexion(s) RDP détectée(s)",
            'details': [f"{l['user']} depuis {l.get('source_ip', '?')} à {l['time']}" for l in rdp_logins[:3]]
        })
    
    # 7. Modifications pare-feu
    fw_events = query_event_log_powershell('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', [2004, 2005, 2006], hours_back=24)
    if fw_events:
        results['alerts'].append({
            'rule': 'firewall_change',
            'severity': 'high',
            'description': f"{len(fw_events)} modification(s) du pare-feu",
            'details': [e.get('message', '')[:100] for e in fw_events[:3]]
        })
    
    # Calculer le résumé
    for alert in results['alerts']:
        severity = alert['severity']
        results['summary'][severity] = results['summary'].get(severity, 0) + 1
    results['summary']['total_alerts'] = len(results['alerts'])
    
    # Évaluer le risque global
    if results['summary']['critical'] > 0:
        results['risk_level'] = 'critical'
    elif results['summary']['high'] >= 2:
        results['risk_level'] = 'high'
    elif results['summary']['high'] >= 1 or results['summary']['medium'] >= 3:
        results['risk_level'] = 'medium'
    else:
        results['risk_level'] = 'low'
    
    # Recommandations
    results['recommendations'] = generate_log_recommendations(results)
    
    return results


def generate_log_recommendations(results):
    """Génère des recommandations basées sur l'analyse des logs."""
    recommendations = []
    
    if results['failed_logins'].get('detected'):
        recommendations.append("URGENT: Activez le verrouillage de compte après 5 tentatives échouées")
        recommendations.append("Configurez une politique de mots de passe forts")
    
    for alert in results['alerts']:
        if alert['rule'] == 'audit_log_cleared':
            recommendations.append("CRITIQUE: Enquêtez immédiatement sur l'effacement des logs")
        elif alert['rule'] == 'service_manipulation':
            recommendations.append("Vérifiez les nouveaux services installés (possible malware)")
        elif alert['rule'] == 'firewall_change':
            recommendations.append("Vérifiez les modifications du pare-feu (règles non autorisées)")
        elif alert['rule'] == 'powershell_suspicious':
            recommendations.append("Activez la journalisation PowerShell complète et vérifiez les scripts")
    
    if not recommendations:
        recommendations.append("OK: Aucune activité suspecte détectée dans les journaux système")
    
    return recommendations


if __name__ == "__main__":
    result = run_log_analysis()
    print(json.dumps(result, indent=2, default=str))
