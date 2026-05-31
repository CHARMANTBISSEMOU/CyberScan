"""
CyberScan - Module Integrity Check (Tripwire-style)
Vérifie l'intégrité des fichiers système critiques via hashing SHA-256.
Détecte les modifications suspectes de fichiers importants.
"""

import hashlib
import os
import json
import logging
import tempfile
from datetime import datetime

# Fichier de baseline (hashes de référence)
BASELINE_FILE = os.path.join(tempfile.gettempdir(), '.cyberscan_agent', 'integrity_baseline.json')

# Fichiers et dossiers critiques à surveiller
CRITICAL_PATHS = {
    'system_files': [
        r'C:\Windows\System32\drivers\etc\hosts',
        r'C:\Windows\System32\config\SAM',
        r'C:\Windows\System32\cmd.exe',
        r'C:\Windows\System32\powershell.exe',
        r'C:\Windows\System32\net.exe',
        r'C:\Windows\System32\net1.exe',
        r'C:\Windows\System32\netsh.exe',
        r'C:\Windows\System32\schtasks.exe',
        r'C:\Windows\System32\reg.exe',
        r'C:\Windows\System32\wscript.exe',
        r'C:\Windows\System32\cscript.exe',
        r'C:\Windows\System32\mshta.exe',
        r'C:\Windows\System32\rundll32.exe',
        r'C:\Windows\System32\regsvr32.exe',
    ],
    'startup_locations': [
        os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
        os.path.join(os.environ.get('PROGRAMDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
    ],
    'boot_files': [
        r'C:\Windows\System32\bootmgr',
        r'C:\Windows\System32\winload.exe',
    ],
    'critical_configs': [
        r'C:\Windows\System32\drivers\etc\hosts',
        r'C:\Windows\System32\drivers\etc\services',
        r'C:\Windows\System32\drivers\etc\protocol',
    ]
}


def hash_file(filepath):
    """Calcule le hash SHA-256 d'un fichier."""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        return "ACCESS_DENIED"
    except FileNotFoundError:
        return "NOT_FOUND"
    except Exception as e:
        return f"ERROR:{str(e)[:50]}"


def get_file_info(filepath):
    """Récupère les métadonnées d'un fichier."""
    try:
        stat = os.stat(filepath)
        return {
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }
    except:
        return {'size': 0, 'modified': 'unknown', 'created': 'unknown'}


def scan_startup_folder(folder_path):
    """Liste les fichiers dans un dossier de démarrage."""
    files = []
    try:
        if os.path.exists(folder_path):
            for item in os.listdir(folder_path):
                full_path = os.path.join(folder_path, item)
                if os.path.isfile(full_path):
                    files.append({
                        'name': item,
                        'path': full_path,
                        'hash': hash_file(full_path),
                        'info': get_file_info(full_path)
                    })
    except Exception:
        pass
    return files


def load_baseline():
    """Charge la baseline de hashes."""
    try:
        if os.path.exists(BASELINE_FILE):
            with open(BASELINE_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return None


def save_baseline(hashes):
    """Sauvegarde la baseline de hashes."""
    try:
        os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
        with open(BASELINE_FILE, 'w') as f:
            json.dump(hashes, f, indent=2)
    except Exception as e:
        logging.error(f"Erreur sauvegarde baseline: {e}")


def run_integrity_check():
    """Exécute la vérification d'intégrité complète."""
    results = {
        'scan_time': datetime.now().isoformat(),
        'files_checked': 0,
        'files_ok': 0,
        'files_modified': [],
        'files_missing': [],
        'files_new': [],
        'files_access_denied': [],
        'startup_items': [],
        'risk_level': 'low',
        'baseline_exists': False,
        'current_hashes': {}
    }
    
    # Calculer les hashes actuels
    current_hashes = {}
    
    for category, paths in CRITICAL_PATHS.items():
        if category == 'startup_locations':
            # Scanner les dossiers de démarrage
            for folder in paths:
                startup_files = scan_startup_folder(folder)
                results['startup_items'].extend(startup_files)
                for sf in startup_files:
                    current_hashes[sf['path']] = sf['hash']
        else:
            for filepath in paths:
                file_hash = hash_file(filepath)
                current_hashes[filepath] = file_hash
                results['files_checked'] += 1
                
                if file_hash == "ACCESS_DENIED":
                    results['files_access_denied'].append(filepath)
                elif file_hash == "NOT_FOUND":
                    results['files_missing'].append(filepath)
                elif file_hash.startswith("ERROR:"):
                    results['files_access_denied'].append(filepath)
    
    results['current_hashes'] = current_hashes
    
    # Comparer avec la baseline
    baseline = load_baseline()
    
    if baseline:
        results['baseline_exists'] = True
        baseline_hashes = baseline.get('hashes', {})
        
        for filepath, current_hash in current_hashes.items():
            if current_hash in ("ACCESS_DENIED", "NOT_FOUND") or current_hash.startswith("ERROR:"):
                continue
            
            if filepath in baseline_hashes:
                if baseline_hashes[filepath] != current_hash:
                    results['files_modified'].append({
                        'path': filepath,
                        'old_hash': baseline_hashes[filepath][:16] + '...',
                        'new_hash': current_hash[:16] + '...',
                        'info': get_file_info(filepath)
                    })
                else:
                    results['files_ok'] += 1
            else:
                results['files_new'].append({
                    'path': filepath,
                    'hash': current_hash[:16] + '...',
                    'info': get_file_info(filepath)
                })
        
        # Fichiers disparus depuis la baseline
        for filepath in baseline_hashes:
            if filepath not in current_hashes:
                results['files_missing'].append(filepath)
    else:
        # Pas de baseline → première exécution, tout est OK
        results['files_ok'] = results['files_checked'] - len(results['files_access_denied']) - len(results['files_missing'])
    
    # Sauvegarder la nouvelle baseline
    valid_hashes = {k: v for k, v in current_hashes.items() 
                    if v not in ("ACCESS_DENIED", "NOT_FOUND") and not v.startswith("ERROR:")}
    save_baseline({
        'timestamp': datetime.now().isoformat(),
        'hashes': valid_hashes
    })
    
    # Évaluation du risque
    modified_count = len(results['files_modified'])
    suspicious_startup = len(results['startup_items'])
    
    if modified_count >= 3 or any('cmd.exe' in f.get('path', '') or 'powershell' in f.get('path', '') 
                                   for f in results['files_modified']):
        results['risk_level'] = 'critical'
    elif modified_count >= 1:
        results['risk_level'] = 'high'
    elif suspicious_startup >= 5:
        results['risk_level'] = 'medium'
    else:
        results['risk_level'] = 'low'
    
    # Recommandations
    results['recommendations'] = generate_integrity_recommendations(results)
    
    # Nettoyer les hashes bruts pour réduire la taille
    del results['current_hashes']
    
    return results


def generate_integrity_recommendations(results):
    """Génère des recommandations d'intégrité."""
    recommendations = []
    
    if results['files_modified']:
        recommendations.append(f"ALERTE: {len(results['files_modified'])} fichier(s) système modifié(s) depuis le dernier scan")
        for f in results['files_modified'][:3]:
            recommendations.append(f"  → {os.path.basename(f['path'])} modifié le {f['info']['modified']}")
    
    if len(results['startup_items']) > 3:
        recommendations.append(f"ATTENTION: {len(results['startup_items'])} élément(s) au démarrage - Vérifiez leur légitimité")
    
    if results['files_missing']:
        recommendations.append(f"INFO: {len(results['files_missing'])} fichier(s) système manquant(s)")
    
    if not results['baseline_exists']:
        recommendations.append("INFO: Première analyse - Baseline de référence créée")
    
    if not recommendations:
        recommendations.append("OK: Aucune modification détectée sur les fichiers système critiques")
    
    return recommendations


if __name__ == "__main__":
    result = run_integrity_check()
    print(json.dumps(result, indent=2, default=str))
