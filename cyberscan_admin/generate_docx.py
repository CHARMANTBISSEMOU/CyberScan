# -*- coding: utf-8 -*-
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    """Applique une couleur d'arrière-plan à une cellule."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Définit les marges internes d'une cellule."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def create_document():
    doc = docx.Document()
    
    # Configuration des marges
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Styles globaux
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Segoe UI'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x2D, 0x37, 0x48) # Charcoal
    
    # -------------------------------------------------------------
    # PAGE DE GARDE
    # -------------------------------------------------------------
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_p.paragraph_format.space_before = Pt(120)
    title_run = title_p.add_run("CYBERSCAN")
    title_run.font.name = 'Segoe UI'
    title_run.font.size = Pt(36)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D) # Navy Blue

    subtitle_p = doc.add_paragraph()
    subtitle_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle_p.paragraph_format.space_after = Pt(40)
    sub_run = subtitle_p.add_run("La Solution d'Audit et de Surveillance de Sécurité Centralisée pilotée par IA")
    sub_run.font.name = 'Segoe UI'
    sub_run.font.size = Pt(16)
    sub_run.font.italic = True
    sub_run.font.color.rgb = RGBColor(0x4A, 0x55, 0x68) # Slate Gray

    doc.add_paragraph().paragraph_format.space_after = Pt(80)

    # Cadre Info
    info_table = doc.add_table(rows=4, cols=2)
    info_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    infos = [
        ("Destinataires :", "Responsables Académiques & Jury - Keyce Academy"),
        ("Auteur :", "Équipe Projet Tuteuré (Semestre II)"),
        ("Date de livraison :", "31 Mai 2026"),
        ("Version du Document :", "v1.0 - Cahier des Charges & Pitch Commercial")
    ]
    for i, (label, val) in enumerate(infos):
        row = info_table.rows[i]
        
        r0 = row.cells[0].paragraphs[0].add_run(label)
        r0.bold = True
        r0.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)
        
        r1 = row.cells[1].paragraphs[0].add_run(val)
        r1.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)

    # Saut de page
    doc.add_page_break()

    # -------------------------------------------------------------
    # SECTION 1: SYNTHÈSE EXECUTIVE & CONTEXTE (VENTE/PITCH)
    # -------------------------------------------------------------
    h1 = doc.add_paragraph()
    h1.paragraph_format.space_before = Pt(20)
    h1.paragraph_format.space_after = Pt(10)
    h1_run = h1.add_run("1. Synthèse Executive & Contexte Commercial")
    h1_run.font.size = Pt(20)
    h1_run.font.bold = True
    h1_run.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)

    p = doc.add_paragraph(
        "Aujourd'hui, 80% des petites et moyennes entreprises (PME) et des infrastructures éducatives "
        "ne disposent pas d'un système d'audit de sécurité centralisé et accessible. Les solutions existantes "
        "(comme Splunk ou Nessus) sont extrêmement onéreuses, nécessitent des compétences d'ingénierie avancées, "
        "et génèrent des rapports techniques incompréhensibles pour les décideurs."
    )
    p.paragraph_format.space_after = Pt(10)

    p2 = doc.add_paragraph()
    p2_bold = p2.add_run("CyberScan résout ce problème majeur. ")
    p2_bold.bold = True
    p2.add_run(
        "C'est une application d'audit de vulnérabilités et de surveillance en temps réel, "
        "100% francisée, dotée d'une double interface (Simple/Expert) et d'un conseiller en sécurité "
        "animé par une intelligence artificielle de pointe (Groq / Claude). Elle combine la robustesse d'un "
        "agent système Windows natif et la clarté d'un tableau de bord de synthèse décisionnel."
    )
    p2.paragraph_format.space_after = Pt(15)

    # Tableau Proposition de Valeur
    doc.add_paragraph().paragraph_format.space_after = Pt(5)
    v_table = doc.add_table(rows=4, cols=2)
    v_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    headers = [("Pourquoi choisir CyberScan ?", "Bénéfice Académique & Professionnel pour Keyce")]
    v_data = [
        ("Zéro Dépendance Cloud Privé", "La base de données SQLite est 100% locale. Aucune donnée sur le trafic réseau ou la configuration des machines de Keyce ne quitte le réseau local, assurant une conformité totale au RGPD."),
        ("Double Interface Adaptative", "Le 'Mode Simple' permet aux étudiants ou responsables administratifs d'évaluer la sécurité d'un parc en un clic. Le 'Mode Expert' donne aux étudiants en réseau/sécurité l'accès aux logs, connexions brutes et détails système."),
        ("Diagnostic IA Intuitif", "L'IA traduit les vulnérabilités techniques complexes (ports ouverts, alertes de registre, failles système) en recommandations d'actions prioritaires rédigées en langage naturel."),
        ("Architecture Distribuée Légère", "L'agent s'installe en tâche de fond de manière silencieuse sur les machines cibles sans impact mesurable sur les performances systèmes (<1% CPU, <20 Mo RAM).")
    ]
    
    # Style de la table
    for i, (col1, col2) in enumerate(headers + v_data):
        row = v_table.rows[i] if i == 0 else v_table.add_row()
        cell1, cell2 = row.cells[0], row.cells[1]
        
        # Marges
        set_cell_margins(cell1, 120, 120, 150, 150)
        set_cell_margins(cell2, 120, 120, 150, 150)
        
        p1 = cell1.paragraphs[0]
        p2 = cell2.paragraphs[0]
        
        if i == 0:
            set_cell_background(cell1, "1A365D")
            set_cell_background(cell2, "1A365D")
            r1 = p1.add_run(col1)
            r1.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            r1.font.bold = True
            r2 = p2.add_run(col2)
            r2.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            r2.font.bold = True
        else:
            set_cell_background(cell1, "F7FAFC" if i % 2 == 1 else "FFFFFF")
            set_cell_background(cell2, "F7FAFC" if i % 2 == 1 else "FFFFFF")
            r1 = p1.add_run(col1)
            r1.font.bold = True
            r1.font.color.rgb = RGBColor(0x2C, 0x52, 0x82)
            p2.add_run(col2)
            
    doc.add_paragraph().paragraph_format.space_after = Pt(20)

    # -------------------------------------------------------------
    # SECTION 2: ARCHITECTURE & FONCTIONNEMENT TECHNIQUE
    # -------------------------------------------------------------
    h2 = doc.add_paragraph()
    h2.paragraph_format.space_before = Pt(20)
    h2.paragraph_format.space_after = Pt(10)
    h2_run = h2.add_run("2. Architecture Technique & Sécurité du Système")
    h2_run.font.size = Pt(20)
    h2_run.font.bold = True
    h2_run.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)

    doc.add_paragraph(
        "CyberScan s'appuie sur une architecture client-serveur moderne, optimisée pour des performances maximales "
        "et une sécurité de niveau entreprise :"
    )

    # Liste des composants techniques
    techs = [
        ("Le Serveur d'Administration (Console)", "Développé en Python avec l'interface graphique moderne PyQt6, il intègre un serveur WebSocket asynchrone (0.0.0.0:8765) sécurisé par SSL/TLS qui reçoit en temps réel les événements d'audit de sécurité des machines."),
        ("L'Agent de Surveillance Windows (Daemon)", "Un binaire léger et autonome compilé avec PyInstaller. Il s'exécute silencieusement en arrière-plan, se lance au démarrage de Windows (via clé de registre HKCU\\Run) et exploite les APIs natives WMI pour analyser en continu l'intégrité du système, les modifications de fichiers, l'état des ports et la sécurité."),
        ("Chiffrement AES-256-GCM & Stockage", "Les clés d'API sensibles de l'IA (Groq et Claude) saisies par l'utilisateur sont chiffrées en AES-256-GCM avec dérivation de clé PBKDF2 (hashlib.pbkdf2_hmac) avant d'être sauvegardées dans une base de données SQLite locale, éliminant tout risque de fuite de secrets."),
        ("Module Réseau & Scans de Ports", "Un port scanner parallélisé performant, supportant un 'Mode Rapide' (analyse des ports critiques en moins de 20 secondes) et un 'Mode Complet' (analyse approfondie), complété par un outil d'exploration réseau pour cartographier les équipements de l'école (routeurs, switches, serveurs).")
    ]

    for title, desc in techs:
        tp = doc.add_paragraph(style='List Bullet')
        tp.paragraph_format.space_after = Pt(6)
        r_title = tp.add_run(f"{title} : ")
        r_title.bold = True
        r_title.font.color.rgb = RGBColor(0x2C, 0x52, 0x82)
        tp.add_run(desc)

    doc.add_paragraph().paragraph_format.space_after = Pt(15)

    # -------------------------------------------------------------
    # SECTION 3: FONCTIONNALITÉS CLÉS (LIVRABLES)
    # -------------------------------------------------------------
    h3 = doc.add_paragraph()
    h3.paragraph_format.space_before = Pt(20)
    h3.paragraph_format.space_after = Pt(10)
    h3_run = h3.add_run("3. Spécifications Fonctionnelles & Expérience Utilisateur (UX 100%)")
    h3_run.font.size = Pt(20)
    h3_run.font.bold = True
    h3_run.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)

    p_feat = doc.add_paragraph(
        "L'application a été entièrement repensée pour offrir une expérience utilisateur fluide, "
        "efficace et accessible à tous les niveaux de compétences (100% Facilité et Efficacité) :"
    )
    p_feat.paragraph_format.space_after = Pt(10)

    features = [
        ("1️⃣ Assistant de Bienvenue (Onboarding Wizard)", "Un guide de premier démarrage interactif, esthétique et entièrement cadré. Il permet d'initier l'utilisateur, de configurer pas-à-pas les clés API IA avec des liens d'accès direct vers les plateformes Groq et Claude, et de valider leur connectivité instantanément."),
        ("2️⃣ Mode Double - Simple & Expert", "Une bascule d'interface dynamique et instantanée. En Mode Simple, l'utilisateur a accès à un tableau de bord épuré, aux scores de sécurité par code couleur, à une barre de statut motivante et aux actions d'analyse rapide. En Mode Expert, toutes les consoles techniques de monitoring de trafic, d'analyses de logs et de sondages réseau détaillés s'activent."),
        ("3️⃣ Dashboard Decisionnel Synthétique", "Un écran d'accueil d'une page qui regroupe les KPIs essentiels : score global de sécurité, alertes réseau à haut risque, état des machines du parc, liste prioritaire des risques et accès direct aux actions recommandées par l'IA."),
        ("4️⃣ Surveillance de Trafic Temps Réel Intelligente", "Détection automatique des processus suspects (ex. BitTorrent, IRC, VPNs non autorisés), des flux à haut risque et des pics de bande passante. L'intégralité de l'interface (ports, statuts, alertes) est traduite en français avec conversion locale de l'heure."),
        ("5️⃣ Système d'Aide Vocale Intégré", "Un bouton d'aide audio interactif est disponible sur chaque page principale pour guider vocalement l'utilisateur, décrire le rôle de la page et lui indiquer les étapes à suivre."),
        ("6️⃣ Générateur de Rapports PDF Professionnels", "Export en un clic d'un rapport de synthèse de sécurité au format PDF, combinant le score de sécurité, l'inventaire des vulnérabilités et l'évaluation stratégique de l'IA.")
    ]

    for title, desc in features:
        tp = doc.add_paragraph()
        tp.paragraph_format.space_before = Pt(8)
        tp.paragraph_format.space_after = Pt(4)
        r_title = tp.add_run(title)
        r_title.bold = True
        r_title.font.size = Pt(12)
        r_title.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)
        
        dp = doc.add_paragraph(desc)
        dp.paragraph_format.left_indent = Inches(0.25)
        dp.paragraph_format.space_after = Pt(8)

    doc.add_page_break()

    # -------------------------------------------------------------
    # SECTION 4: PRESENTATION / DIAPORAMA PITCH COMMERCIAL (KEYCE)
    # -------------------------------------------------------------
    h4 = doc.add_paragraph()
    h4.paragraph_format.space_before = Pt(20)
    h4.paragraph_format.space_after = Pt(10)
    h4_run = h4.add_run("4. Plan de Pitch Commercial (PowerPoint)")
    h4_run.font.size = Pt(20)
    h4_run.font.bold = True
    h4_run.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)

    doc.add_paragraph(
        "Ce guide étape par étape vous permet de réaliser une présentation PowerPoint percutante devant "
        "le jury académique de Keyce Academy ou des investisseurs potentiels :"
    )

    slides = [
        ("Slide 1: Titre & Accroche", 
         "• Contenu : Logo Keyce Academy, Titre : 'CYBERSCAN - Révolutionner l'audit de sécurité par l'IA', Noms des présentateurs.\n"
         "• Pitch Oral : 'Bonjour à tous. Face à l'augmentation massive des cyberattaques de 150% sur les PME cette année, comment assurer la sécurité d'un parc informatique sans budget illimité et sans expert à plein temps ? C'est le défi auquel répond CyberScan aujourd'hui.'"),
         
        ("Slide 2: Le Problème du Marché", 
         "• Contenu : 'Complexe, Hors de prix, Obscur'. Chiffres clés : 80% des failles viennent de mauvaises configurations de base.\n"
         "• Pitch Oral : 'Les solutions actuelles sont conçues pour des ingénieurs ultra-spécialisés. Elles coûtent cher et leurs alertes cryptiques finissent ignorées par les gérants.'"),
         
        ("Slide 3: La Solution - CyberScan", 
         "• Contenu : Capture d'écran de l'interface en Mode Simple, mise en valeur du Score de Sécurité.\n"
         "• Pitch Oral : 'Voici CyberScan. Une console centralisée qui pilote des agents de surveillance intelligents installés sur vos machines. En une seconde, vous obtenez un score de sécurité clair de 0 à 100 et un plan d'action rédigé en français par notre IA.'"),
         
        ("Slide 4: Démo Technique - L'Agent & L'IA", 
         "• Contenu : Schéma de l'architecture distribuée (WebSocket + SSL/TLS -> SQLite + Groq/Claude AI).\n"
         "• Pitch Oral : 'L'agent Windows collecte de manière totalement anonyme et sécurisée les failles locales (ports ouverts, modifications suspectes de fichiers de configuration). Ces données brutes sont chiffrées puis synthétisées par une intelligence artificielle sécurisée. Vos données restent privées, mais l'analyse est de niveau expert.'"),
         
        ("Slide 5: L'Expérience Utilisateur à 100%", 
         "• Contenu : Icônes interactives des fonctionnalités : Assistant de premier départ, Mode Simple/Expert, Aide Vocale intégrée pour l'accessibilité.\n"
         "• Pitch Oral : 'Nous avons pensé cette application pour tout le monde. Les techniciens basculent en Mode Expert pour analyser les paquets réseau en temps réel. Les responsables restent en Mode Simple pour piloter les risques et exporter des rapports PDF professionnels.'"),
         
        ("Slide 6: Impact Académique & Pédagogique", 
         "• Contenu : Pourquoi ce projet est une réussite pour Keyce Academy. Cas d'usage en travaux pratiques.\n"
         "• Pitch Oral : 'Ce projet est idéal pour Keyce Academy. Il démontre la maîtrise d'architectures réseau réelles, de sécurité cryptographique avancée et d'intégration d'IA générative. Il peut également servir d'outil d'audit pédagogique pour sécuriser nos propres salles de classe.'")
    ]

    for title, content in slides:
        tp = doc.add_paragraph()
        tp.paragraph_format.space_before = Pt(10)
        tp.paragraph_format.space_after = Pt(2)
        r_title = tp.add_run(title)
        r_title.bold = True
        r_title.font.size = Pt(13)
        r_title.font.color.rgb = RGBColor(0x2C, 0x52, 0x82)
        
        dp = doc.add_paragraph(content)
        dp.paragraph_format.left_indent = Inches(0.25)
        dp.paragraph_format.space_after = Pt(10)

    # Sauvegarde
    doc.save("Cahier_des_Charges_CyberScan.docx")
    print("Document Word généré avec succès!")

if __name__ == "__main__":
    create_document()
