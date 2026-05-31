import wmi
import win32evtlog
import win32net
import win32netcon
import win32security
import logging
import subprocess
import os
import socket
import ctypes
from datetime import datetime, timedelta

# Flag pour masquer les fenêtres console des subprocess
NO_WINDOW = subprocess.CREATE_NO_WINDOW

# ============================================================
# MODULE 1 : Informations Système & Pare-feu
# ============================================================
def get_system_info():
    """Récupère les infos OS, pare-feu détaillé, mises à jour manquantes"""
    result = {
        "os_name": "Unknown",
        "os_version": "Unknown",
        "os_build": "Unknown",
        "os_architecture": "Unknown",
        "last_boot_time": "Unknown",
        "firewall": {},
        "pending_updates": [],
        "installed_updates_count": 0
    }
    
    try:
        c = wmi.WMI()
        os_info = c.Win32_OperatingSystem()[0]
        result["os_name"] = os_info.Caption
        result["os_version"] = os_info.Version
        result["os_build"] = os_info.BuildNumber
        result["os_architecture"] = os_info.OSArchitecture
        result["last_boot_time"] = os_info.LastBootUpTime
    except Exception as e:
        logging.error(f"Erreur récupération info OS: {e}")

    # Pare-feu détaillé (chaque profil)
    try:
        fw_mgr = wmi.WMI(namespace="root/StandardCimv2")
        for fw in fw_mgr.MSFT_NetFirewallProfile():
            result["firewall"][fw.Name] = {
                "enabled": bool(fw.Enabled),
                "default_inbound_action": "Block" if fw.DefaultInboundAction == 1 else "Allow",
                "default_outbound_action": "Block" if fw.DefaultOutboundAction == 1 else "Allow"
            }
    except Exception as e:
        logging.error(f"Vérification pare-feu échouée (nécessite admin): {e}")
        result["firewall"] = {"error": "Accès refusé - Lancez l'agent en administrateur"}

    # Mises à jour installées
    try:
        c = wmi.WMI()
        updates = c.Win32_QuickFixEngineering()
        result["installed_updates_count"] = len(updates)
        # Vérifier les mises à jour récentes (< 90 jours)
        recent_cutoff = datetime.now() - timedelta(days=90)
        recent_updates = []
        for u in updates[-10:]:  # 10 dernières
            recent_updates.append({
                "hotfix_id": u.HotFixID,
                "description": u.Description or "N/A",
                "installed_on": str(u.InstalledOn) if u.InstalledOn else "Unknown"
            })
        result["recent_updates"] = recent_updates
    except Exception as e:
        logging.error(f"Erreur récupération mises à jour: {e}")

    # Vérifier les mises à jour en attente via PowerShell
    try:
        ps_cmd = 'powershell -Command "try { $sess = New-Object -ComObject Microsoft.Update.Session; $search = $sess.CreateUpdateSearcher(); $result = $search.Search(\'IsInstalled=0\'); $result.Updates | Select-Object -First 10 Title | ConvertTo-Json } catch { Write-Output \'[]\'  }"'
        proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=30, shell=True, creationflags=NO_WINDOW)
        if proc.stdout.strip() and proc.stdout.strip() != '[]':
            import json
            try:
                pending = json.loads(proc.stdout.strip())
                if isinstance(pending, dict):
                    pending = [pending]
                result["pending_updates"] = [u.get("Title", str(u)) for u in pending if isinstance(u, dict)]
            except:
                pass
    except Exception as e:
        logging.warning(f"Impossible de vérifier les mises à jour en attente: {e}")

    return result

# ============================================================
# MODULE 2 : Scan des Ports Ouverts & Services
# ============================================================
def get_open_ports():
    """Détecte les ports ouverts et services actifs via netstat"""
    ports = []
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, timeout=15, creationflags=NO_WINDOW
        )
        for line in proc.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 5 and parts[0] == 'TCP':
                local_addr = parts[1]
                state = parts[3]
                pid = parts[4]
                if state == 'LISTENING' and ('0.0.0.0:' in local_addr or '[::]' in local_addr):
                    port = local_addr.split(':')[-1]
                    # Identifier le processus
                    proc_name = get_process_name(pid)
                    ports.append({
                        "port": int(port),
                        "state": state,
                        "pid": pid,
                        "process": proc_name,
                        "risk": classify_port_risk(int(port))
                    })
    except Exception as e:
        logging.error(f"Erreur scan ports: {e}")
    return ports

def get_process_name(pid):
    """Récupère le nom du processus par PID"""
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5, creationflags=NO_WINDOW
        )
        if proc.stdout.strip():
            return proc.stdout.strip().split(',')[0].strip('"')
    except:
        pass
    return "Unknown"

def classify_port_risk(port):
    """Classifie le niveau de risque d'un port ouvert"""
    critical_ports = {23: "Telnet (non chiffré)", 21: "FTP (non chiffré)", 
                      445: "SMB (cible fréquente)", 3389: "RDP (accès distant)",
                      1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL"}
    medium_ports = {80: "HTTP", 8080: "HTTP Proxy", 135: "RPC", 139: "NetBIOS",
                    5900: "VNC", 5985: "WinRM"}
    
    if port in critical_ports:
        return {"level": "critical", "description": critical_ports[port]}
    elif port in medium_ports:
        return {"level": "medium", "description": medium_ports[port]}
    return {"level": "low", "description": "Port standard"}

# ============================================================
# MODULE 3 : Analyse des Journaux d'Événements (Complet)
# ============================================================
EVENT_ID_MAP = {
    4624: "Connexion réussie",
    4625: "Tentative de connexion échouée",
    4720: "Nouveau compte utilisateur créé",
    4732: "Compte ajouté au groupe Administrateurs",
    4648: "Connexion avec identifiants explicites",
    7045: "Nouveau service installé",
}

USB_EVENT_IDS = {2003: "Périphérique USB branché", 2100: "Périphérique USB retiré"}

def get_event_logs():
    """Lit les logs Security pour connexions, brute force, USB, services suspects"""
    events_found = []
    brute_force_attempts = {}
    watermark_file = "last_event_record.txt"
    last_record = 0
    
    if os.path.exists(watermark_file):
        try:
            with open(watermark_file, "r") as f:
                last_record = int(f.read().strip())
        except:
            pass

    # --- Logs Security ---
    try:
        hand = win32evtlog.OpenEventLog('localhost', 'Security')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        highest_record = last_record
        target_ids = set(EVENT_ID_MAP.keys())
        
        count = 0
        while events and count < 500:
            for event in events:
                if event.RecordNumber <= last_record:
                    events = None
                    break
                if event.RecordNumber > highest_record:
                    highest_record = event.RecordNumber
                    
                event_id = event.EventID & 0xFFFF
                if event_id in target_ids:
                    evt_data = {
                        "event_id": event_id,
                        "type": EVENT_ID_MAP[event_id],
                        "time": event.TimeGenerated.Format(),
                        "source": event.SourceName or "Unknown"
                    }
                    # Extraction des détails des strings
                    if event.StringInserts:
                        strings = list(event.StringInserts)
                        if event_id == 4624 and len(strings) > 8:
                            evt_data["username"] = strings[5] if len(strings) > 5 else "N/A"
                            evt_data["logon_type"] = strings[8] if len(strings) > 8 else "N/A"
                            evt_data["source_ip"] = strings[18] if len(strings) > 18 else "N/A"
                        elif event_id == 4625 and len(strings) > 5:
                            evt_data["username"] = strings[5] if len(strings) > 5 else "N/A"
                            evt_data["source_ip"] = strings[19] if len(strings) > 19 else "N/A"
                            # Compteur brute force
                            key = evt_data.get("source_ip", "unknown")
                            brute_force_attempts[key] = brute_force_attempts.get(key, 0) + 1
                        elif event_id == 4720 and len(strings) > 0:
                            evt_data["new_account"] = strings[0]
                        elif event_id == 4732 and len(strings) > 0:
                            evt_data["account_added"] = strings[0]
                            evt_data["group"] = strings[2] if len(strings) > 2 else "N/A"
                        elif event_id == 7045 and len(strings) > 1:
                            evt_data["service_name"] = strings[0]
                            evt_data["service_path"] = strings[1] if len(strings) > 1 else "N/A"
                    
                    events_found.append(evt_data)
                count += 1
                if count >= 500:
                    break
            if not events or count >= 500:
                break
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
        win32evtlog.CloseEventLog(hand)
        
        if highest_record > last_record:
            with open(watermark_file, "w") as f:
                f.write(str(highest_record))
                
    except Exception as e:
        logging.error(f"Erreur lecture journal Sécurité: {e}")
        events_found.append({"error": "Accès refusé au journal Sécurité. Lancez l'agent en Administrateur."})

    # --- Logs System (USB + Services) ---
    try:
        hand = win32evtlog.OpenEventLog('localhost', 'System')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        count = 0
        while events and count < 200:
            for event in events:
                event_id = event.EventID & 0xFFFF
                if event_id in USB_EVENT_IDS:
                    events_found.append({
                        "event_id": event_id,
                        "type": USB_EVENT_IDS[event_id],
                        "time": event.TimeGenerated.Format(),
                        "source": "System"
                    })
                elif event_id == 7045:
                    evt_data = {
                        "event_id": event_id,
                        "type": "Nouveau service installé",
                        "time": event.TimeGenerated.Format(),
                        "source": "System"
                    }
                    if event.StringInserts and len(event.StringInserts) > 1:
                        evt_data["service_name"] = event.StringInserts[0]
                        evt_data["service_path"] = event.StringInserts[1]
                    events_found.append(evt_data)
                count += 1
                if count >= 200:
                    break
            if not events or count >= 200:
                break
            events = win32evtlog.ReadEventLog(hand, flags, 0)
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        logging.warning(f"Impossible de lire le journal Système: {e}")

    # Résumé brute force
    brute_force_summary = []
    for ip, count in brute_force_attempts.items():
        if count >= 3:
            brute_force_summary.append({
                "source_ip": ip,
                "failed_attempts": count,
                "alert": f"{count} tentatives échouées depuis {ip} — Possible attaque brute-force"
            })

    return {
        "events": events_found,
        "brute_force_alerts": brute_force_summary,
        "total_events_analyzed": len(events_found)
    }

# ============================================================
# MODULE 4 : Audit des Comptes Locaux
# ============================================================
def get_local_accounts():
    """Récupère les utilisateurs locaux avec détails : admin, inactif, invité, sans mot de passe"""
    accounts = []
    try:
        resume = 0
        while True:
            users, total, resume = win32net.NetUserEnum(None, 2, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
            for user in users:
                flags = user.get('flags', 0)
                is_disabled = bool(flags & 0x0002)  # UF_ACCOUNTDISABLE
                no_password = bool(flags & 0x0020)  # UF_PASSWD_NOTREQD
                password_expired = bool(flags & 0x800000)  # UF_PASSWORD_EXPIRED
                last_logon = user.get('last_logon', 0)
                
                # Calculer l'inactivité
                days_inactive = None
                if last_logon and last_logon > 0:
                    from datetime import datetime, timezone
                    # Windows epoch: Jan 1, 1970
                    try:
                        last_logon_dt = datetime.fromtimestamp(last_logon)
                        days_inactive = (datetime.now() - last_logon_dt).days
                    except:
                        pass
                
                accounts.append({
                    "username": user['name'],
                    "full_name": user.get('full_name', ''),
                    "is_admin": user['priv'] == win32netcon.USER_PRIV_ADMIN,
                    "is_disabled": is_disabled,
                    "no_password_required": no_password,
                    "password_expired": password_expired,
                    "days_inactive": days_inactive,
                    "comment": user.get('comment', ''),
                    "is_guest": user['name'].lower() in ['guest', 'invité', 'invite']
                })
            if resume == 0:
                break
    except Exception as e:
        logging.error(f"Erreur récupération comptes: {e}")
    return accounts

# ============================================================
# MODULE 5 : Audit des Partages Réseau
# ============================================================
def get_network_shares():
    """Liste les dossiers partagés avec permissions et détection de risques"""
    shares = []
    try:
        resume = 0
        while True:
            share_list, total, resume = win32net.NetShareEnum(None, 2, resume)
            for share in share_list:
                share_info = {
                    "name": share['netname'],
                    "path": share['path'],
                    "remark": share['remark'],
                    "type": share['type'],
                    "is_disk_share": share['type'] == 0,
                    "permissions": share.get('permissions', 'N/A'),
                    "max_uses": share.get('max_uses', 'N/A'),
                    "current_uses": share.get('current_uses', 0),
                }
                # Vérifier si le partage est un partage administratif ($)
                share_info["is_admin_share"] = share['netname'].endswith('$')
                
                # Vérifier si le dossier existe et contient des fichiers
                if share['path'] and os.path.isdir(share['path']):
                    try:
                        files = os.listdir(share['path'])
                        share_info["file_count"] = len(files)
                        share_info["is_empty"] = len(files) == 0
                    except PermissionError:
                        share_info["file_count"] = "Accès refusé"
                        share_info["is_empty"] = None
                
                shares.append(share_info)
            if resume == 0:
                break
    except Exception as e:
        logging.error(f"Erreur récupération partages: {e}")
    return shares

# ============================================================
# MODULE 6 : Processus Suspects
# ============================================================
SUSPECT_PATHS = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
SUSPECT_NAMES = ["svchost32", "csrss2", "lsass2", "explorer2", "cmd_hidden", "powershell_hidden"]

def get_running_processes():
    """Détecte les processus suspects (chemins temporaires, noms usurpés) — via psutil (rapide)"""
    suspicious = []
    all_processes_count = 0
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            all_processes_count += 1
            try:
                info = proc.info
                name = info.get('name') or ""
                path = info.get('exe') or ""
                
                is_suspect = False
                reasons = []
                
                for sp in SUSPECT_PATHS:
                    if sp in path.lower():
                        is_suspect = True
                        reasons.append(f"Lancé depuis un dossier temporaire: {path}")
                        break
                
                name_lower = name.lower().replace('.exe', '')
                for sn in SUSPECT_NAMES:
                    if name_lower == sn:
                        is_suspect = True
                        reasons.append(f"Nom suspect (usurpation de processus système): {name}")
                        break
                
                if is_suspect:
                    cmdline = info.get('cmdline') or []
                    suspicious.append({
                        "name": name,
                        "pid": info['pid'],
                        "path": path,
                        "command_line": (' '.join(cmdline))[:200],
                        "reasons": reasons
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logging.error(f"Erreur analyse processus: {e}")
    
    return {
        "total_processes": all_processes_count,
        "suspicious_processes": suspicious
    }

# ============================================================
# MODULE 7 : Services Windows Suspects
# ============================================================
def get_services_audit():
    """Vérifie les services installés pour détecter les services suspects — via psutil + sc query (rapide)"""
    services = []
    try:
        import psutil
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                path = info.get('binpath') or ""
                is_suspect = False
                reasons = []
                
                if path:
                    path_lower = path.lower()
                    for sp in SUSPECT_PATHS:
                        if sp in path_lower:
                            is_suspect = True
                            reasons.append(f"Service lancé depuis chemin suspect: {path}")
                    
                    if not ("system32" in path_lower or "program files" in path_lower or "syswow64" in path_lower):
                        if info.get('start_type') == 'automatic' and info.get('status') == 'running':
                            is_suspect = True
                            reasons.append(f"Service auto-démarré depuis un chemin non standard")
                
                if is_suspect:
                    services.append({
                        "name": info.get('name', 'N/A'),
                        "display_name": info.get('display_name', 'N/A'),
                        "path": path[:200],
                        "state": info.get('status', 'Unknown'),
                        "start_mode": info.get('start_type', 'Unknown'),
                        "reasons": reasons
                    })
            except Exception:
                continue
    except Exception as e:
        logging.error(f"Erreur audit services: {e}")
    return services

# ============================================================
# MODULE 8 : Antivirus / Windows Defender Status
# ============================================================
def get_antivirus_status():
    """Vérifie le statut de l'antivirus (Windows Defender ou autre)"""
    result = {
        "antivirus_products": [],
        "defender_status": {},
        "recent_threats": []
    }
    
    # Via WMI SecurityCenter2
    try:
        c = wmi.WMI(namespace="root/SecurityCenter2")
        for av in c.AntiVirusProduct():
            state = av.productState
            # Décodage du productState
            enabled = bool((state >> 12) & 1)
            up_to_date = not bool((state >> 4) & 1)
            result["antivirus_products"].append({
                "name": av.displayName,
                "enabled": enabled,
                "up_to_date": up_to_date,
                "path": av.pathToSignedProductExe or "N/A"
            })
    except Exception as e:
        logging.warning(f"Impossible d'accéder à SecurityCenter2: {e}")
    
    # Windows Defender status via PowerShell
    try:
        ps_cmd = 'powershell -Command "try { Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge | ConvertTo-Json } catch { Write-Output \'{}\' }"'
        proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=15, shell=True, creationflags=NO_WINDOW)
        if proc.stdout.strip() and proc.stdout.strip() != '{}':
            import json
            try:
                defender = json.loads(proc.stdout.strip())
                result["defender_status"] = {
                    "running_mode": defender.get("AMRunningMode", "Unknown"),
                    "antivirus_enabled": defender.get("AntivirusEnabled", False),
                    "realtime_protection": defender.get("RealTimeProtectionEnabled", False),
                    "signatures_last_updated": str(defender.get("AntivirusSignatureLastUpdated", "Unknown")),
                    "quick_scan_age_days": defender.get("QuickScanAge", "Unknown"),
                    "full_scan_age_days": defender.get("FullScanAge", "Unknown")
                }
            except:
                pass
    except Exception as e:
        logging.warning(f"Impossible de vérifier Windows Defender: {e}")
    
    # Menaces récentes de Defender
    try:
        ps_cmd = 'powershell -Command "try { Get-MpThreatDetection | Select-Object -First 5 ThreatID, ProcessName, DomainUser, ActionSuccess, InitialDetectionTime | ConvertTo-Json } catch { Write-Output \'[]\' }"'
        proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=15, shell=True, creationflags=NO_WINDOW)
        if proc.stdout.strip() and proc.stdout.strip() != '[]':
            import json
            try:
                threats = json.loads(proc.stdout.strip())
                if isinstance(threats, dict):
                    threats = [threats]
                result["recent_threats"] = threats
            except:
                pass
    except Exception as e:
        logging.warning(f"Impossible de récupérer les menaces Defender: {e}")
    
    return result

# ============================================================
# MODULE 9 : Programmes Installés
# ============================================================
def get_installed_programs():
    """Liste les programmes installés via le registre (instantané, remplace Win32_Product qui prend 2+ min)"""
    programs = []
    try:
        import winreg
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        seen = set()
        for hive, reg_path in paths:
            try:
                key = winreg.OpenKey(hive, reg_path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        if name in seen:
                            continue
                        seen.add(name)
                        vendor = ""
                        version = ""
                        try: vendor = winreg.QueryValueEx(subkey, "Publisher")[0]
                        except: pass
                        try: version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        except: pass
                        programs.append({"name": name, "vendor": vendor, "version": version})
                    except:
                        pass
            except:
                pass
    except Exception as e:
        logging.error(f"Erreur récupération programmes: {e}")
    
    return programs[:50]  # Limiter à 50 pour ne pas surcharger l'IA

# ============================================================
# FONCTION PRINCIPALE : Exécuter tous les modules
# ============================================================
def run_all_scans(mode='full'):
    """Exécute tous les modules de scan Windows et retourne le résultat complet.
    
    Args:
        mode: 'full' pour scan complet (60-90s), 'quick' pour scan rapide (15-20s)
    """
    logging.info(f"=== Démarrage du scan CyberScan (mode: {mode}) ===")
    
    results = {}
    import time
    import concurrent.futures

    start_ts = time.time()
    is_quick = (mode == 'quick')

    # Préparer des wrappers pour les modules lourds importés à la volée
    def _activity():
        import activity_logger
        return activity_logger.get_and_clear_activities()

    def _portscan():
        import port_scanner
        # Mode rapide: scan réduit aux ports critiques uniquement
        if is_quick:
            return port_scanner.run_port_scan_quick()
        return port_scanner.run_port_scan()

    def _integrity():
        import integrity_check
        return integrity_check.run_integrity_check()

    def _loganalysis():
        import log_analyzer
        return log_analyzer.run_log_analysis()
    
    def _programs_quick():
        # Mode rapide: limiter aux 20 programmes les plus récents
        progs = get_installed_programs()
        if isinstance(progs, list) and len(progs) > 20:
            return progs[:20]
        return progs

    if is_quick:
        # Mode RAPIDE: modules essentiels seulement, timeouts courts
        tasks = [
            ("system_info", "Informations Système", get_system_info, 3),
            ("open_ports", "Ports Ouverts", get_open_ports, 5),
            ("event_logs", "Journaux Événements", get_event_logs, 5),
            ("local_accounts", "Comptes Locaux", get_local_accounts, 3),
            ("processes", "Processus", get_running_processes, 5),
            ("suspicious_services", "Services", get_services_audit, 4),
            ("antivirus", "Antivirus", get_antivirus_status, 3),
            ("installed_programs", "Programmes", _programs_quick, 5),
            ("user_activities", "Activités", _activity, 5),
            ("port_scan", "Port Scan (rapide)", _portscan, 10),
            # Skip en mode rapide: integrity_check, log_analysis, network_shares
        ]
    else:
        # Mode COMPLET: tous les modules
        tasks = [
            ("system_info", "Informations Système & Pare-feu", get_system_info, 3),
            ("open_ports", "Ports Ouverts & Services Actifs", get_open_ports, 8),
            ("event_logs", "Journaux d'Événements (Sécurité)", get_event_logs, 10),
            ("local_accounts", "Audit des Comptes Locaux", get_local_accounts, 5),
            ("network_shares", "Audit des Partages Réseau", get_network_shares, 8),
            ("processes", "Processus Suspects", get_running_processes, 8),
            ("suspicious_services", "Services Windows Suspects", get_services_audit, 6),
            ("antivirus", "Antivirus & Windows Defender", get_antivirus_status, 6),
            ("installed_programs", "Programmes Installés", get_installed_programs, 10),
            ("user_activities", "Activités Utilisateur", _activity, 15),
            ("port_scan", "Scan de Ports (nmap-style)", _portscan, 60),
            ("integrity_check", "Vérification d'Intégrité (Tripwire-style)", _integrity, 25),
            ("log_analysis", "Analyse des Logs (logcheck-style)", _loganalysis, 45),
        ]

    # Exécuter en parallèle, le temps total ≈ max des timeouts effectifs
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {}
        for key, label, func, timeout_s in tasks:
            logging.info(f"  → Module: {label}...")
            start_mod = time.time()
            fut = executor.submit(func)
            futures[fut] = (key, label, timeout_s, start_mod)

        for fut in concurrent.futures.as_completed(futures):
            key, label, timeout_s, start_mod = futures[fut]
            try:
                # La future est déjà terminée (as_completed), result() sans timeout est OK
                res = fut.result()
                results[key] = res
                dur = time.time() - start_mod
                logging.info(f"  ✓ {label} terminé en {dur:.1f}s")
            except concurrent.futures.TimeoutError:
                logging.warning(f"  ⚠ {label}: timeout ({timeout_s}s)")
                # Valeurs par défaut adaptées
                if key == "user_activities":
                    results[key] = {"apps_opened": [], "websites_visited": [], "error": "timeout"}
                elif key == "port_scan":
                    results[key] = {"error": "timeout", "open_ports": []}
                elif key == "log_analysis":
                    results[key] = {"error": "timeout", "alerts": []}
                elif key == "integrity_check":
                    results[key] = {"error": "timeout", "files_modified": []}
                else:
                    results[key] = {"error": "timeout"}
            except Exception as e:
                logging.error(f"  ✗ {label} échoué: {e}")
                # Valeurs par défaut adaptées
                if key == "user_activities":
                    results[key] = {"apps_opened": [], "websites_visited": [], "error": str(e)}
                elif key == "port_scan":
                    results[key] = {"error": str(e), "open_ports": []}
                elif key == "log_analysis":
                    results[key] = {"error": str(e), "alerts": []}
                elif key == "integrity_check":
                    results[key] = {"error": str(e), "files_modified": []}
                else:
                    results[key] = {"error": str(e)}

    total_dur = time.time() - start_ts
    logging.info(f"=== Scan complet terminé en {total_dur:.1f}s ===")
    return results

if __name__ == "__main__":
    import json
    print(json.dumps(run_all_scans(), indent=2, default=str))
