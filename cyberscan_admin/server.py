import asyncio
import websockets
import ssl
import json
import logging
import hashlib
import socket
import base64
import os
import sys
import tempfile
from database import CyberScanDB
import ia_analyzer
import pdf_generator
from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialiser la BDD
db = CyberScanDB()

def get_local_ip():
    """Obtient l'IP locale de la machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Store connected agents: {websocket: agent_info_dict}
connected_agents = {}

def get_data_hash(data):
    """Hash des données système uniquement (exclut user_activities pour éviter de relancer l'IA à chaque scan)."""
    data_for_hash = {k: v for k, v in data.items() if k != 'user_activities'} if isinstance(data, dict) else data
    return hashlib.sha256(json.dumps(data_for_hash, sort_keys=True, default=str).encode()).hexdigest()

def generate_and_encode_pdf(machine_info, ai_report, actions_only=False):
    """Génère un PDF en mémoire et retourne son contenu en base64.
    actions_only=True : PDF simplifié avec uniquement les actions de maintenance (pour les cibles).
    actions_only=False : PDF complet confidentiel (pour l'admin).
    """
    try:
        tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
        tmp_path = tmp.name
        tmp.close()
        if actions_only:
            pdf_generator.generate_actions_pdf_report(machine_info, ai_report, tmp_path)
        else:
            pdf_generator.generate_pdf_report(machine_info, ai_report, tmp_path)
        with open(tmp_path, 'rb') as f:
            pdf_bytes = f.read()
        os.unlink(tmp_path)
        return base64.b64encode(pdf_bytes).decode('utf-8')
    except Exception as e:
        logging.error(f"Erreur génération PDF : {e}")
        return None

async def request_scan(websocket, agent_info, mode='full'):
    """Envoie une demande de scan à un agent connecté.
    
    Args:
        mode: 'full' pour scan complet (~60-90s), 'quick' pour scan rapide (~15-20s)
    """
    try:
        await websocket.send(json.dumps({'action': 'scan', 'mode': mode}))
        logging.info(f"Demande de scan ({mode}) envoyée à {agent_info.get('hostname', 'unknown')}")
    except Exception as e:
        logging.error(f"Erreur envoi scan : {e}")

async def request_email_check(websocket, emails, api_key):
    """Envoie une demande de vérification d'emails à un agent."""
    try:
        await websocket.send(json.dumps({
            'action': 'check_emails',
            'emails': emails,
            'api_key': api_key
        }))
    except Exception as e:
        logging.error(f"Erreur envoi vérification email : {e}")

async def send_pdf_to_agent(websocket, machine_info, ai_report, hostname):
    """Génère et envoie un PDF simplifié (actions uniquement) au bureau de la machine cible."""
    pdf_b64 = generate_and_encode_pdf(machine_info, ai_report, actions_only=True)
    if pdf_b64:
        from datetime import datetime
        filename = f"CyberScan_Rapport_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        await websocket.send(json.dumps({
            'action': 'deliver_pdf',
            'pdf_base64': pdf_b64,
            'filename': filename
        }))
        logging.info(f"PDF envoyé à {hostname} pour sauvegarde sur le bureau")

async def handler(websocket):
    try:
        message = await websocket.recv()
        data = json.loads(message)
        
        if data.get('action') == 'register':
            agent_id = data.get('agent_id')
            os_name = data.get('os')
            hostname = data.get('hostname')
            remote_ip = websocket.remote_address[0] if websocket.remote_address else None
            client_ip = data.get('local_ip') or remote_ip
            
            connected_agents[websocket] = {
                'id': agent_id,
                'os': os_name,
                'hostname': hostname,
                'ip': client_ip
            }
            db.register_machine(agent_id, hostname, os_name, client_ip)
            
            logging.info(f"Agent enregistré : {hostname} ({os_name}) - ID: {agent_id} - IP: {client_ip}")
            
            await websocket.send(json.dumps({'status': 'registered', 'message': 'Bienvenue sur CyberScan Admin'}))
            
            # Scan initial automatique (mode complet par défaut)
            logging.info(f"Demande de scan initial à {hostname} (mode: full)...")
            await websocket.send(json.dumps({'action': 'scan', 'mode': 'full'}))
            
            async for msg in websocket:
                try:
                    payload = json.loads(msg)
                    action = payload.get('action', '')
                    # Mettre à jour last_seen à chaque message de l'agent
                    try:
                        db.heartbeat(agent_id)
                    except Exception:
                        pass
                    
                    if action == 'scan_status':
                        status = payload.get('status', '')
                        logging.info(f"{hostname} : statut scan = {status}")
                        # Tracker les machines en cours de scan pour l'animation UI
                        try:
                            import app as app_module
                            if status == 'scanning':
                                app_module.scanning_machines.add(agent_id)
                            else:
                                app_module.scanning_machines.discard(agent_id)
                        except (ImportError, AttributeError):
                            pass
                        continue
                    
                    if action == 'scan_result':
                        # Retirer de la liste des machines en cours de scan
                        try:
                            import app as app_module
                            app_module.scanning_machines.discard(agent_id)
                            app_module.scan_progress_done = min(
                                app_module.scan_progress_done + 1,
                                app_module.scan_progress_total or app_module.scan_progress_done + 1
                            )
                        except (ImportError, AttributeError):
                            pass
                        raw_data = payload.get('data')
                        # Détecter une erreur critique de l'agent (scan planté)
                        if isinstance(raw_data, dict) and 'error' in raw_data and len(raw_data) <= 3:
                            err = raw_data.get('error')
                            tb = raw_data.get('traceback', '')
                            logging.error(f"[AGENT {hostname}] Scan PLANTE: {err}")
                            if tb:
                                logging.error(f"[AGENT {hostname}] Traceback:\n{tb}")
                            try:
                                import app as app_module
                                app_module.last_ai_error = f"Agent {hostname} a plante: {err}"
                            except Exception:
                                pass
                            # Ne pas appeler l'IA sur des données vides
                            agent_error_report = {
                                "raw_data": raw_data,
                                "ai_report": {
                                    "score": 0,
                                    "ai_error": f"Agent error: {err}",
                                    "summary": f"Le scan agent a plante: {err}",
                                    "risks": [],
                                    "recommendations": [
                                        "Lancer l'agent en tant qu'Administrateur",
                                        "Verifier que tous les modules de l'agent sont installes",
                                    ],
                                },
                            }
                            db.save_scan_result(agent_id, 0, agent_error_report)
                            continue
                        current_hash = get_data_hash(raw_data)
                        
                        latest_scan = db.get_latest_scan(agent_id)
                        
                        skip_ai = False
                        if latest_scan:
                            last_full_result = json.loads(latest_scan['json_data'])
                            if 'raw_data' in last_full_result:
                                last_hash = get_data_hash(last_full_result['raw_data'])
                                if current_hash == last_hash:
                                    skip_ai = True
                        
                        if skip_ai:
                            logging.info(f"Données identiques pour {hostname}. Analyse IA ignorée.")
                            db.update_machine_status(agent_id, 'online')
                            db.register_machine(agent_id, hostname, os_name, client_ip)
                        else:
                            logging.info(f"Analyse IA (chunked) pour {hostname}...")
                            try:
                                import app as app_module
                            except Exception:
                                app_module = None

                            def _progress_cb(step, total, label):
                                if app_module is not None:
                                    try:
                                        app_module.scan_step_total = total
                                        app_module.scan_step_done = step
                                        app_module.scan_step_label = f"{hostname}: {label}"
                                    except Exception:
                                        pass

                            ai_report = await asyncio.to_thread(
                                ia_analyzer.analyze_scan_chunked, db, raw_data, _progress_cb
                            )
                            score = ai_report.get('score', 0)
                            
                            full_result = {
                                "raw_data": raw_data,
                                "ai_report": ai_report
                            }
                            
                            db.save_scan_result(agent_id, score, full_result)
                            logging.info(f"Scan sauvegardé pour {hostname}. Score : {score}")
                            try:
                                import app as app_module
                                app_module.last_ai_error = ai_report.get('ai_error') if score == 0 else None
                                app_module.scan_step_done = 0
                                app_module.scan_step_label = ""
                            except Exception:
                                pass
                            
                            # Envoyer automatiquement le PDF au bureau de la machine cible
                            machine_info = {
                                'hostname': hostname,
                                'os_name': os_name,
                                'ip_address': client_ip
                            }
                            try:
                                await send_pdf_to_agent(websocket, machine_info, ai_report, hostname)
                            except Exception as e:
                                logging.error(f"Erreur envoi PDF à {hostname} : {e}")
                    
                    elif action == 'email_check_result':
                        results = payload.get('results', [])
                        logging.info(f"Résultats HIBP reçus de {hostname}: {len(results)} email(s)")
                        # Sauvegarder dans le dernier scan
                        latest_scan = db.get_latest_scan(agent_id)
                        if latest_scan:
                            scan_data = json.loads(latest_scan['json_data'])
                            scan_data['email_breach_results'] = results
                            db.save_scan_result(agent_id, latest_scan['score'], scan_data)
                    
                    elif action == 'pdf_delivered':
                        path = payload.get('path', '')
                        logging.info(f"PDF délivré sur {hostname} : {path}")
                    
                    elif action == 'pong':
                        continue
                    
                except json.JSONDecodeError:
                    logging.error(f"JSON invalide reçu de {hostname}")
                    
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        logging.error(f"Erreur gestion connexion : {e}")
    finally:
        if websocket in connected_agents:
            info = connected_agents.pop(websocket)
            db.update_machine_status(info['id'], 'offline')
            logging.info(f"Agent déconnecté : {info['hostname']}")

async def scheduled_scan_loop():
    """Boucle de scan programmé — vérifie chaque minute si un scan est prévu."""
    while True:
        try:
            schedule_time = db.get_api_key("ScheduledScanTime")
            if schedule_time:
                from datetime import datetime
                now = datetime.now()
                current_time = now.strftime("%H:%M")
                if current_time == schedule_time:
                    logging.info(f"=== Scan programmé déclenché à {current_time} ===")
                    for ws, agent_info in list(connected_agents.items()):
                        try:
                            await request_scan(ws, agent_info)
                        except Exception as e:
                            logging.error(f"Erreur scan programmé pour {agent_info.get('hostname')}: {e}")
                    # Attendre 61 secondes pour ne pas re-déclencher la même minute
                    await asyncio.sleep(61)
                    continue
        except Exception as e:
            logging.error(f"Erreur boucle scan programmé: {e}")
        await asyncio.sleep(30)

async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    if getattr(sys, 'frozen', False):
        base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
    cert_path = os.path.join(base_dir, "certs", "cert.pem")
    key_path = os.path.join(base_dir, "certs", "key.pem")
    if not os.path.exists(cert_path) and getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        cert_path = os.path.join(exe_dir, "certs", "cert.pem")
        key_path = os.path.join(exe_dir, "certs", "key.pem")
    
    try:
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    except Exception as e:
        logging.error(f"Impossible de charger les certificats depuis {cert_path}: {e}")
        raise
    
    server_ip = "0.0.0.0"
    server_port = 8765
    local_ip = get_local_ip()
    
    logging.info(f"Démarrage du serveur CyberScan sur wss://{server_ip}:{server_port}")
    logging.info(f"IP locale : {local_ip}")
    
    aio_zc = AsyncZeroconf()
    try:
        ip_bytes = socket.inet_aton(local_ip)
    except Exception:
        ip_bytes = b'\x7f\x00\x00\x01'
        
    hostname = socket.gethostname().replace(" ", "-") + ".local."
    
    info = ServiceInfo(
        "_cyberscan._tcp.local.",
        "CyberScan Server._cyberscan._tcp.local.",
        addresses=[ip_bytes],
        port=server_port,
        properties={'version': '2.0'},
        server=hostname
    )
    
    await aio_zc.async_register_service(info)
    logging.info("Service mDNS enregistré.")
    
    # Démarrer la boucle de scan programmé en arrière-plan
    asyncio.create_task(scheduled_scan_loop())
    
    try:
        async with websockets.serve(handler, server_ip, server_port, ssl=ssl_context, ping_interval=20, ping_timeout=60):
            logging.info(f"Serveur WebSocket CyberScan actif sur le port {server_port}")
            await asyncio.Future()
    finally:
        await aio_zc.async_unregister_service(info)
        await aio_zc.async_close()

if __name__ == "__main__":
    asyncio.run(main())
