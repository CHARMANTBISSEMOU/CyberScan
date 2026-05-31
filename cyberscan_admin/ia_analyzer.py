import json
import logging
import re
from groq import Groq
import anthropic

def _parse_ai_json(text):
    """Parse une réponse IA en JSON, en supprimant les wrappers markdown éventuels."""
    if text is None:
        raise ValueError("Réponse vide")
    s = text.strip()
    # Retirer les wrappers ```json ... ``` ou ``` ... ```
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.IGNORECASE)
        s = re.sub(r"\s*```\s*$", "", s)
    # Tenter directement
    try:
        return json.loads(s)
    except Exception:
        # Fallback: extraire le premier objet JSON {...}
        m = re.search(r"\{.*\}", s, flags=re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise

# Découpage des modules en groupes pour appels IA séparés (3 chunks pour limiter rate-limit)
CHUNKS = [
    {
        "name": "Sécurité système et ports",
        "modules": ["system_info", "open_ports", "antivirus", "port_scan"],
        "focus": "OS, pare-feu, mises à jour, ports ouverts, antivirus."
    },
    {
        "name": "Comptes, journaux et intégrité",
        "modules": ["local_accounts", "event_logs", "integrity_check", "log_analysis"],
        "focus": "Comptes locaux, brute force, USB, intégrité fichiers, intrusions."
    },
    {
        "name": "Processus, services et activité",
        "modules": ["processes", "suspicious_services", "network_shares", "installed_programs", "user_activities"],
        "focus": "Processus suspects, services anormaux, partages, logiciels, activité utilisateur."
    },
]

CHUNK_PROMPT = """
Tu es ingénieur cybersécurité. Analyse UNIQUEMENT le sous-ensemble suivant des données Windows : {focus}
Réponds en JSON valide UNIQUEMENT, format obligatoire :
{{
  "chunk": "{chunk_name}",
  "sub_score": 0-100,
  "summary": "résumé court 1-2 phrases",
  "risks": [
    {{"level":"critical|high|medium|low","module":"...","title":"...","description":"...","remediation":"..."}}
  ],
  "module_analysis": {{"<module>":"<analyse>"}}
}}
Règles de scoring identiques au système CyberScan : 0-20 critique, 21-40 élevé, 41-60 moyen, 61-80 bon, 81-100 excellent.
"""

SYNTHESIS_PROMPT = """
Tu reçois 4 sous-analyses CyberScan d'une même machine. Produis la synthèse finale UNIQUEMENT en JSON :
{
  "score": 0-100 (moyenne pondérée des sub_score, pondérer plus fort les chunks contenant des risques critiques),
  "summary": "résumé exécutif global 2-3 phrases",
  "risks": [...consolidés triés par sévérité...],
  "recommendations": [{"priority":"urgent|high|medium|low","action":"...","command":"...","impact":"..."}],
  "module_analysis": {fusionner les module_analysis des sous-analyses},
  "predictive_analysis": {"attack_scenario":"...","correction_scenario":"...","estimated_time_to_fix":"..."},
  "diagnostic_expert": "..."
}
Échelle: 0-20 critique, 21-40 élevé, 41-60 moyen, 61-80 bon, 81-100 excellent.
"""

def _call_ai(db, system_prompt, user_payload):
    """Appelle l'IA configurée en testant les fournisseurs jusqu'à succès. Retourne dict JSON."""
    default_api = db.get_api_key("Default_API") or "Groq_1"
    providers = ["Groq_1", "Groq_2", "Groq_3", "Claude"]
    if default_api in providers:
        providers.remove(default_api)
        providers.insert(0, default_api)

    # Modèles Groq actuellement supportés (mai 2026)
    groq_models = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]
    # Modèles Claude supportés
    claude_models = ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307"]

    attempts = []
    for provider in providers:
        api_key = db.get_api_key(provider)
        if not api_key or api_key.strip() == "":
            continue
        try:
            if provider.startswith("Groq"):
                client = Groq(api_key=api_key.strip())
                for model in groq_models:
                    try:
                        cc = client.chat.completions.create(
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": json.dumps(user_payload)},
                            ],
                            model=model,
                            temperature=0,
                            response_format={"type": "json_object"},
                        )
                        return _parse_ai_json(cc.choices[0].message.content)
                    except Exception as me:
                        attempts.append(f"{provider}/{model}: {me}")
                        continue
            elif provider == "Claude":
                client = anthropic.Anthropic(api_key=api_key.strip())
                provider_404 = False
                for model in claude_models:
                    try:
                        msg = client.messages.create(
                            model=model,
                            max_tokens=4096,
                            system=system_prompt,
                            messages=[{"role": "user", "content": json.dumps(user_payload)}],
                        )
                        return _parse_ai_json(msg.content[0].text)
                    except Exception as me:
                        err_str = str(me)
                        attempts.append(f"Claude/{model}: {me}")
                        # Si la clé n'a accès à aucun modèle (404 not_found), inutile d'essayer les autres
                        if "404" in err_str or "not_found" in err_str:
                            provider_404 = True
                            break
                        continue
                if provider_404:
                    continue  # passer au prochain provider sans essayer les autres modèles Claude
        except Exception as e:
            attempts.append(f"{provider}: {e}")
            continue
    raise RuntimeError("\n".join(attempts) or "Aucune clé API configurée")


def analyze_scan_chunked(db, scan_data, progress_cb=None):
    """Analyse en plusieurs requêtes IA pour fluidité et réduction de charge par appel.
    progress_cb(step_index, total_steps, label) appelé avant/après chaque étape.
    Retourne un rapport au format compatible avec le rapport classique.
    """
    total_steps = len(CHUNKS) + 1  # 4 chunks + 1 synthèse
    sub_reports = []
    errors = []

    for i, chunk in enumerate(CHUNKS):
        if progress_cb:
            progress_cb(i, total_steps, f"Analyse: {chunk['name']}")
        sub_payload = {m: scan_data.get(m) for m in chunk["modules"] if m in scan_data}
        prompt = CHUNK_PROMPT.format(focus=chunk["focus"], chunk_name=chunk["name"])
        try:
            sub = _call_ai(db, prompt, sub_payload)
            sub_reports.append(sub)
        except Exception as e:
            errors.append(f"{chunk['name']}: {e}")
            sub_reports.append({"chunk": chunk["name"], "sub_score": 0, "summary": "échec analyse partielle", "risks": [], "module_analysis": {}})

    if progress_cb:
        progress_cb(len(CHUNKS), total_steps, "Synthèse finale")

    try:
        final = _call_ai(db, SYNTHESIS_PROMPT, {"sub_reports": sub_reports})
    except Exception as e:
        errors.append(f"synthèse: {e}")
        # Fallback: synthèse locale en moyennant les sub_score
        scores = [s.get("sub_score", 0) for s in sub_reports if isinstance(s.get("sub_score"), (int, float))]
        avg = int(sum(scores) / len(scores)) if scores else 0
        merged_risks = []
        merged_module = {}
        for s in sub_reports:
            merged_risks.extend(s.get("risks", []))
            merged_module.update(s.get("module_analysis", {}))
        final = {
            "score": avg,
            "summary": "Synthèse locale (l'IA finale a échoué).",
            "risks": merged_risks,
            "recommendations": [],
            "module_analysis": merged_module,
        }

    if errors:
        final["ai_partial_errors"] = errors

    if progress_cb:
        progress_cb(total_steps, total_steps, "Terminé")

    return final


def analyze_scan_with_ai(db, scan_data):
    """
    Envoie les données brutes à l'API via un pool avec basculement automatique.
    Commence par la clé par défaut, puis essaie toutes les autres.
    """
    # Récupérer le fournisseur par défaut
    default_api = db.get_api_key("Default_API") or "Groq_1"
    
    # Construire la liste des fournisseurs disponibles
    providers = ["Groq_1", "Groq_2", "Groq_3", "Claude"]
    
    # Mettre le fournisseur par défaut en premier, puis les autres
    if default_api in providers:
        providers.remove(default_api)
        providers.insert(0, default_api)
        
    system_prompt = """
    Tu es un ingénieur en cybersécurité senior travaillant pour CyberScan.
    Tu vas recevoir un payload JSON contenant les données brutes collectées sur une machine Windows via 10 modules d'audit :
    1. system_info : OS, pare-feu (par profil), mises à jour installées/en attente
    2. open_ports : ports TCP ouverts, processus associés, niveau de risque
    3. event_logs : événements de sécurité (connexions, brute force, USB, services installés)
    4. local_accounts : comptes locaux (admin, invité, inactifs, sans mot de passe)
    5. network_shares : partages réseau (permissions, contenu)
    6. processes : processus suspects (chemins temporaires, noms usurpés)
    7. suspicious_services : services Windows lancés depuis des chemins inhabituels
    8. antivirus : statut antivirus, Windows Defender, menaces récentes
    9. installed_programs : logiciels installés
    10. user_activities : ACTIVITÉS DE L'UTILISATEUR entre deux scans :
        - apps_opened : applications lancées par l'utilisateur (nom du processus + date)
        - websites_visited : sites web visités (navigateur, URL, titre de la page, date de visite)
        - collection_period : période de collecte des données
    
    Ta mission est d'analyser CHAQUE module en profondeur et de retourner un rapport d'audit DÉTAILLÉ au format JSON.
    
    IMPORTANT : Pour chaque vulnérabilité détectée, tu DOIS fournir :
    - La description précise du problème
    - Le module source (d'où vient la détection)
    - La remédiation concrète étape par étape (commandes Windows si applicable)
    - Le niveau de risque (critical, high, medium, low)
    
    Format de réponse obligatoire (uniquement du JSON valide, rien d'autre, pas de markdown, pas de commentaires) :
    {
      "score": 42,
      "summary": "Résumé exécutif en 2-3 phrases de l'état de sécurité global.",
      "risks": [
        {
          "level": "critical",
          "module": "open_ports",
          "title": "Port Telnet (23) ouvert",
          "description": "Le port 23 (Telnet) est ouvert et écoute sur toutes les interfaces. Telnet transmet les données en clair, incluant les identifiants.",
          "remediation": "Désactivez Telnet : Panneau de configuration > Programmes > Activer ou désactiver des fonctionnalités Windows > Décochez Client Telnet. Ou via PowerShell : Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient"
        },
        {
          "level": "high",
          "module": "local_accounts",
          "title": "Compte Guest actif",
          "description": "Le compte invité (Guest) est activé, permettant un accès non authentifié à la machine.",
          "remediation": "Désactivez le compte Guest : net user Guest /active:no"
        }
      ],
      "recommendations": [
        {
          "priority": "urgent",
          "action": "Activer le pare-feu Windows immédiatement",
          "command": "netsh advfirewall set allprofiles state on",
          "impact": "Réduction de 80% de la surface d'attaque"
        }
      ],
      "module_analysis": {
        "system_info": "Analyse détaillée du système...",
        "open_ports": "Analyse détaillée des ports...",
        "event_logs": "Analyse détaillée des logs...",
        "local_accounts": "Analyse détaillée des comptes...",
        "network_shares": "Analyse détaillée des partages...",
        "processes": "Analyse détaillée des processus...",
        "suspicious_services": "Analyse détaillée des services...",
        "antivirus": "Analyse détaillée de l'antivirus...",
        "installed_programs": "Analyse détaillée des programmes...",
        "user_activities": "Analyse du comportement utilisateur : applications suspectes lancées, sites à risque visités, habitudes dangereuses..."
      },
      "predictive_analysis": {
        "attack_scenario": "Si les failles critiques ne sont pas corrigées, un attaquant pourrait...",
        "correction_scenario": "En appliquant les recommandations urgentes, la surface d'attaque serait réduite de X%...",
        "estimated_time_to_fix": "Environ 30 minutes pour les corrections urgentes"
      },
      "diagnostic_expert": "Données techniques brutes pertinentes pour validation par un expert : ports critiques ouverts, Event IDs suspects, etc."
    }
    
    RÈGLES D'ANALYSE :
    - Score 0-20 : CRITIQUE (failles exploitables immédiatement)
    - Score 21-40 : ÉLEVÉ (plusieurs vulnérabilités majeures)
    - Score 41-60 : MOYEN (vulnérabilités modérées)
    - Score 61-80 : BON (quelques points d'amélioration)
    - Score 81-100 : EXCELLENT (sécurité robuste)
    
    - Pare-feu désactivé = risque CRITIQUE
    - Port 23/21 ouvert = risque CRITIQUE
    - Port 3389 ouvert sans restriction = risque ÉLEVÉ
    - Compte Guest actif = risque ÉLEVÉ
    - 3+ tentatives de connexion échouées depuis la même IP = alerte brute force CRITIQUE
    - Mises à jour en attente > 5 = risque MOYEN
    - Processus dans dossier temp = risque ÉLEVÉ
    - Antivirus désactivé ou signatures obsolètes = risque CRITIQUE
    - Partage réseau accessible sans restriction = risque MOYEN
    - Compte inactif > 180 jours avec droits admin = risque ÉLEVÉ
    
    RÈGLES POUR user_activities :
    - Visite de sites de téléchargement illégal, torrent, crack = risque CRITIQUE
    - Visite de sites de phishing connus ou suspects = risque CRITIQUE
    - Utilisation d'applications de contrôle à distance non autorisées (TeamViewer, AnyDesk, etc.) = risque ÉLEVÉ
    - Navigation sur des sites non sécurisés (HTTP sans HTTPS) = risque MOYEN
    - Téléchargement de logiciels depuis des sources non officielles = risque ÉLEVÉ
    - Utilisation excessive de VPN/proxy non autorisés = risque MOYEN
    - Applications de messagerie non approuvées = risque FAIBLE
    - Analyse les habitudes : heures de connexion inhabituelles, volume de navigation anormal
    - Identifie les comportements à risque et propose des sensibilisations ciblées
    
    Si l'accès à certaines données a été refusé, signale-le comme recommandation : "Lancer l'agent en tant qu'administrateur pour obtenir des données complètes".
    Analyse TOUS les modules présents dans le payload, même s'ils sont vides (signale alors "Aucune anomalie détectée").
    """

    # Modèles Groq actuels (mai 2026)
    groq_models = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]
    
    # Modèles Claude supportés
    claude_models = ["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307"]
    
    last_error = None
    attempts = []
    
    for provider in providers:
        api_key = db.get_api_key(provider)
        if not api_key or api_key.strip() == "":
            logging.info(f"Fournisseur {provider} ignoré (pas de clé configurée)")
            continue
            
        logging.info(f"Tentative d'analyse avec le fournisseur : {provider}")
        try:
            if provider.startswith("Groq"):
                client = Groq(api_key=api_key.strip())
                
                # Essayer plusieurs modèles au cas où l'un serait indisponible
                model_error = None
                for model in groq_models:
                    try:
                        logging.info(f"  Essai avec le modèle : {model}")
                        chat_completion = client.chat.completions.create(
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": json.dumps(scan_data)}
                            ],
                            model=model,
                            temperature=0,
                            response_format={"type": "json_object"}
                        )
                        response_text = chat_completion.choices[0].message.content
                        try:
                            result = _parse_ai_json(response_text)
                        except Exception as parse_e:
                            raise RuntimeError(f"Réponse non-JSON de {provider}/{model}: {parse_e} | extrait: {str(response_text)[:200]}")
                        logging.info(f"  ✓ Analyse réussie avec {provider}/{model}")
                        return result
                    except Exception as model_e:
                        model_error = str(model_e)
                        attempts.append(f"{provider}/{model}: {model_error}")
                        logging.warning(f"  Modèle {model} échoué : {model_error}")
                        continue
                
                # Tous les modèles ont échoué pour ce provider
                last_error = f"{provider}: {model_error}"
                
            elif provider == "Claude":
                client = anthropic.Anthropic(api_key=api_key.strip())
                
                model_error = None
                for model in claude_models:
                    try:
                        logging.info(f"  Essai avec le modèle : {model}")
                        message = client.messages.create(
                            model=model,
                            max_tokens=4096,
                            system=system_prompt,
                            messages=[
                                {"role": "user", "content": json.dumps(scan_data)}
                            ]
                        )
                        response_text = message.content[0].text
                        try:
                            result = _parse_ai_json(response_text)
                        except Exception as parse_e:
                            raise RuntimeError(f"Réponse non-JSON de Claude/{model}: {parse_e} | extrait: {str(response_text)[:200]}")
                        logging.info(f"  ✓ Analyse réussie avec Claude/{model}")
                        return result
                    except Exception as model_e:
                        model_error = str(model_e)
                        attempts.append(f"Claude/{model}: {model_error}")
                        logging.warning(f"  Modèle {model} échoué : {model_error}")
                        continue
                
                last_error = f"Claude: {model_error}"
                
        except Exception as e:
            logging.warning(f"Échec avec le fournisseur {provider} : {e}")
            last_error = str(e)
            continue

    # Si on arrive ici, c'est qu'aucun fournisseur n'a fonctionné
    detail = "\n".join(attempts) if attempts else (last_error or "Aucune clé API configurée")
    logging.error(f"Toutes les tentatives d'API ont échoué.\n{detail}")
    return {
        "score": 0,
        "ai_error": detail,
        "summary": f"Échec analyse IA: {last_error or 'aucune clé valide'}",
        "risks": [{"level": "high", "description": f"Impossible d'utiliser l'IA. Détails:\n{detail}"}],
        "recommendations": [
            "Vérifier les clés API dans les paramètres du Dashboard.",
            "S'assurer que les clés sont valides (Groq: console.groq.com / Claude: console.anthropic.com).",
            "Vérifier la connexion internet de cette machine."
        ]
    }

def analyze_network_events_with_ai(db, events_text):
    """Analyse une série d'événements réseau via l'IA."""
    system_prompt = (
        "Vous êtes un expert en cybersécurité. Analysez les événements réseau fournis. "
        "Répondez STRICTEMENT et UNIQUEMENT en JSON selon ce format précis, sans aucun texte autour, sans bloc markdown : "
        '{"summary": "Un résumé global de 2 ou 3 phrases en français", '
        '"details": "Une analyse plus détaillée des événements en français", '
        '"recommendations": ["action 1", "action 2"]}'
    )
    user_payload = f"Événements réseau à analyser :\n{events_text}"
    try:
        return _call_ai(db, system_prompt, user_payload)
    except Exception as e:
        return {
            "summary": "Erreur lors de l'appel à l'IA.",
            "details": str(e),
            "recommendations": []
        }

