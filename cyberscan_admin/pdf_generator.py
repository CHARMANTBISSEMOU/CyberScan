import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime

LEVEL_TRANSLATIONS = {'critical': 'CRITIQUE', 'high': 'ÉLEVÉ', 'medium': 'MOYEN', 'low': 'FAIBLE', 'unknown': 'INCONNU'}
MODULE_NAMES = {
    'system_info': 'Système & Pare-feu',
    'open_ports': 'Ports Ouverts',
    'event_logs': 'Journaux d\'Événements',
    'local_accounts': 'Comptes Locaux',
    'network_shares': 'Partages Réseau',
    'processes': 'Processus',
    'suspicious_services': 'Services Suspects',
    'antivirus': 'Antivirus',
    'installed_programs': 'Programmes Installés',
    'user_activities': 'Activités Utilisateur'
}

def _get_styles():
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=18, spaceAfter=6, textColor=colors.HexColor('#1a365d'))
    heading1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=14, textColor=colors.HexColor('#2c5282'), spaceBefore=16, spaceAfter=8)
    heading2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor('#2d3748'), spaceBefore=10, spaceAfter=6)
    heading3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=10, textColor=colors.HexColor('#4a5568'), spaceBefore=8, spaceAfter=4)
    normal = ParagraphStyle('CustomNormal', parent=styles['Normal'], fontSize=9, leading=13, alignment=TA_JUSTIFY, spaceAfter=4)
    small = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#718096'), spaceAfter=3)
    
    risk_critical = ParagraphStyle('Critical', parent=normal, textColor=colors.HexColor('#c53030'), spaceAfter=4)
    risk_high = ParagraphStyle('High', parent=normal, textColor=colors.HexColor('#dd6b20'), spaceAfter=4)
    risk_medium = ParagraphStyle('Medium', parent=normal, textColor=colors.HexColor('#d69e2e'), spaceAfter=4)
    risk_low = ParagraphStyle('Low', parent=normal, textColor=colors.HexColor('#38a169'), spaceAfter=4)
    
    remediation_style = ParagraphStyle('Remediation', parent=normal, fontSize=8, leftIndent=20, textColor=colors.HexColor('#2b6cb0'), spaceAfter=6, backColor=colors.HexColor('#ebf8ff'))
    command_style = ParagraphStyle('Command', parent=normal, fontSize=8, leftIndent=20, fontName='Courier', textColor=colors.HexColor('#2d3748'), backColor=colors.HexColor('#edf2f7'), spaceAfter=4)
    
    return {
        'title': title_style, 'h1': heading1, 'h2': heading2, 'h3': heading3,
        'normal': normal, 'small': small,
        'critical': risk_critical, 'high': risk_high, 'medium': risk_medium, 'low': risk_low,
        'remediation': remediation_style, 'command': command_style
    }

def _get_risk_style(level, styles):
    level = str(level).lower()
    return styles.get(level, styles['low'])

def _get_score_color(score):
    if score <= 20: return colors.HexColor('#c53030')
    if score <= 40: return colors.HexColor('#dd6b20')
    if score <= 60: return colors.HexColor('#d69e2e')
    if score <= 80: return colors.HexColor('#38a169')
    return colors.HexColor('#276749')

def _get_score_label(score):
    if score <= 20: return 'CRITIQUE'
    if score <= 40: return 'ÉLEVÉ'
    if score <= 60: return 'MOYEN'
    if score <= 80: return 'BON'
    return 'EXCELLENT'

def _safe_str(val, default='N/A'):
    if val is None: return default
    s = str(val)
    # Escape XML special chars for ReportLab
    s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return s if s.strip() else default

def generate_pdf_report(machine_info, ai_report, output_path="report.pdf"):
    """
    Génère un rapport PDF professionnel et détaillé basé sur l'analyse IA.
    """
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm, leftMargin=15*mm, rightMargin=15*mm)
    s = _get_styles()
    story = []
    score = ai_report.get('score', 0)
    if isinstance(score, str):
        try: score = int(score)
        except: score = 0

    # ===== TITRE =====
    story.append(Paragraph(f"Rapport d'Audit Sécurité : {_safe_str(machine_info.get('hostname', 'Machine Inconnue'))}", s['title']))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2c5282')))
    story.append(Spacer(1, 8))

    # ===== INFORMATIONS GÉNÉRALES =====
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score_color = _get_score_color(score)
    score_label = _get_score_label(score)
    
    info_data = [
        ["Date d'Analyse", now],
        ["Machine", _safe_str(machine_info.get('hostname'))],
        ["Adresse IP", _safe_str(machine_info.get('ip_address'))],
        ["Système d'Exploitation", _safe_str(machine_info.get('os_name'))],
        ["Score de Sécurité (IA)", f"{score} / 100 — {score_label}"]
    ]
    
    table = Table(info_data, colWidths=[150, 380])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#edf2f7')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2d3748')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        ('TEXTCOLOR', (1, -1), (1, -1), score_color),
        ('FONTNAME', (1, -1), (1, -1), 'Helvetica-Bold'),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))

    # ===== RÉSUMÉ EXÉCUTIF =====
    summary = ai_report.get('summary', '')
    if summary:
        story.append(Paragraph("Résumé Exécutif", s['h1']))
        story.append(Paragraph(_safe_str(summary), s['normal']))
        story.append(Spacer(1, 12))

    # ===== VULNÉRABILITÉS ET RISQUES =====
    story.append(Paragraph("Vulnérabilités et Risques Détectés", s['h1']))
    story.append(Spacer(1, 6))
    
    risks = ai_report.get('risks', [])
    if not risks:
        story.append(Paragraph("Aucun risque majeur détecté.", s['normal']))
    else:
        # Tableau récapitulatif des risques
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for risk in risks:
            lvl = str(risk.get('level', 'low')).lower()
            if lvl in risk_counts: risk_counts[lvl] += 1
        
        summary_data = [["Critique", "Élevé", "Moyen", "Faible"],
                        [str(risk_counts['critical']), str(risk_counts['high']), str(risk_counts['medium']), str(risk_counts['low'])]]
        summary_table = Table(summary_data, colWidths=[130, 130, 130, 130])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#fed7d7')),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#feebc8')),
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor('#fefcbf')),
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor('#c6f6d5')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTSIZE', (0, 1), (-1, 1), 14),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))
        
        # Détails de chaque risque
        for i, risk in enumerate(risks, 1):
            level = str(risk.get('level', 'unknown')).lower()
            level_fr = LEVEL_TRANSLATIONS.get(level, level.upper())
            title = risk.get('title', risk.get('description', 'Risque non décrit'))
            desc = risk.get('description', '')
            module = risk.get('module', '')
            remediation = risk.get('remediation', '')
            
            module_label = MODULE_NAMES.get(module, module) if module else ''
            module_tag = f" [{module_label}]" if module_label else ''
            
            p_style = _get_risk_style(level, s)
            story.append(Paragraph(f"<b>{i}. [{level_fr}]{module_tag} {_safe_str(title)}</b>", p_style))
            
            if desc and desc != title:
                story.append(Paragraph(_safe_str(desc), s['normal']))
            
            if remediation:
                story.append(Paragraph(f"<b>→ Remédiation :</b> {_safe_str(remediation)}", s['remediation']))
            
            story.append(Spacer(1, 4))
            
    story.append(Spacer(1, 12))

    # ===== RECOMMANDATIONS D'ACTION =====
    story.append(Paragraph("Recommandations d'Action", s['h1']))
    story.append(Spacer(1, 6))
    
    recommendations = ai_report.get('recommendations', [])
    if not recommendations:
        story.append(Paragraph("Aucune recommandation spécifique.", s['normal']))
    else:
        for i, rec in enumerate(recommendations, 1):
            if isinstance(rec, dict):
                priority = rec.get('priority', 'normal')
                action = rec.get('action', str(rec))
                command = rec.get('command', '')
                impact = rec.get('impact', '')
                
                priority_colors = {'urgent': '#c53030', 'high': '#dd6b20', 'normal': '#2d3748', 'low': '#718096'}
                p_color = priority_colors.get(priority, '#2d3748')
                
                story.append(Paragraph(f"<b>{i}.</b> {_safe_str(action)}", s['normal']))
                if command:
                    story.append(Paragraph(f"<font face='Courier' size='8'>{_safe_str(command)}</font>", s['command']))
                if impact:
                    story.append(Paragraph(f"<i>Impact : {_safe_str(impact)}</i>", s['small']))
            else:
                story.append(Paragraph(f"<b>{i}.</b> {_safe_str(str(rec))}", s['normal']))
            story.append(Spacer(1, 4))
            
    story.append(Spacer(1, 12))

    # ===== ANALYSE PAR MODULE =====
    module_analysis = ai_report.get('module_analysis', {})
    if module_analysis:
        story.append(PageBreak())
        story.append(Paragraph("Analyse Détaillée par Module", s['h1']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e0')))
        story.append(Spacer(1, 8))
        
        for module_key, analysis_text in module_analysis.items():
            module_label = MODULE_NAMES.get(module_key, module_key)
            story.append(Paragraph(f"{module_label}", s['h2']))
            story.append(Paragraph(_safe_str(str(analysis_text)), s['normal']))
            story.append(Spacer(1, 8))

    # ===== ANALYSE PRÉDICTIVE =====
    predictive = ai_report.get('predictive_analysis', {})
    if predictive:
        story.append(Paragraph("Analyse Prédictive des Menaces", s['h1']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e0')))
        story.append(Spacer(1, 8))
        
        if isinstance(predictive, dict):
            attack = predictive.get('attack_scenario', '')
            correction = predictive.get('correction_scenario', '')
            time_fix = predictive.get('estimated_time_to_fix', '')
            
            if attack:
                story.append(Paragraph("Scénario d'Attaque", s['h3']))
                story.append(Paragraph(_safe_str(attack), s['normal']))
                story.append(Spacer(1, 6))
            if correction:
                story.append(Paragraph("Scénario de Correction", s['h3']))
                story.append(Paragraph(_safe_str(correction), s['normal']))
                story.append(Spacer(1, 6))
            if time_fix:
                story.append(Paragraph(f"<b>Temps estimé de correction :</b> {_safe_str(time_fix)}", s['normal']))
        else:
            story.append(Paragraph(_safe_str(str(predictive)), s['normal']))
        
        story.append(Spacer(1, 12))

    # ===== DIAGNOSTIC EXPERT =====
    diagnostic = ai_report.get('diagnostic_expert', '')
    if diagnostic:
        story.append(Paragraph("Diagnostic Expert (Données Techniques)", s['h1']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e0')))
        story.append(Spacer(1, 8))
        story.append(Paragraph(_safe_str(str(diagnostic)), s['small']))
        story.append(Spacer(1, 12))

    # ===== PIED DE PAGE =====
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e0')))
    story.append(Spacer(1, 6))
    footer_style = ParagraphStyle('Footer', parent=s['small'], alignment=TA_CENTER, fontSize=7, textColor=colors.HexColor('#a0aec0'))
    story.append(Paragraph(f"Rapport généré automatiquement par CyberScan — {now}", footer_style))
    story.append(Paragraph("Ce document est confidentiel et destiné uniquement à l'administrateur réseau autorisé.", footer_style))

    # Génération
    doc.build(story)
    return output_path


def generate_actions_pdf_report(machine_info, ai_report, output_path="actions_report.pdf"):
    """
    Génère un PDF simplifié destiné aux utilisateurs des machines cibles.
    Contient UNIQUEMENT les actions de maintenance à mener.
    Aucune information sensible (pas de diagnostic, pas de données brutes, pas de score détaillé).
    """
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm, leftMargin=15*mm, rightMargin=15*mm)
    s = _get_styles()
    story = []
    score = ai_report.get('score', 0)
    if isinstance(score, str):
        try: score = int(score)
        except: score = 0

    # ===== TITRE =====
    story.append(Paragraph("Plan de Maintenance Sécurité", s['title']))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2c5282')))
    story.append(Spacer(1, 8))

    # ===== EN-TÊTE SIMPLIFIÉ =====
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score_lbl = _get_score_label(score)
    score_col = _get_score_color(score)

    info_data = [
        ["Date", now],
        ["Machine", _safe_str(machine_info.get('hostname'))],
        ["Niveau de sécurité", f"{score_lbl}"]
    ]
    table = Table(info_data, colWidths=[150, 380])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#edf2f7')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2d3748')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        ('TEXTCOLOR', (1, -1), (1, -1), score_col),
        ('FONTNAME', (1, -1), (1, -1), 'Helvetica-Bold'),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))

    # ===== MESSAGE INTRO =====
    intro_style = ParagraphStyle('Intro', parent=s['normal'], fontSize=10, leading=14, textColor=colors.HexColor('#2d3748'))
    story.append(Paragraph(
        "Ce document liste les actions de maintenance recommandées pour améliorer la sécurité de votre poste. "
        "Veuillez suivre les instructions ci-dessous ou contacter votre administrateur réseau si vous avez besoin d'aide.",
        intro_style
    ))
    story.append(Spacer(1, 16))

    # ===== ACTIONS PRIORITAIRES (REMÉDIATION) =====
    story.append(Paragraph("Actions Prioritaires", s['h1']))
    story.append(Spacer(1, 6))

    risks = ai_report.get('risks', [])
    action_num = 0
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_risks = sorted(risks, key=lambda r: priority_order.get(str(r.get('level', 'low')).lower(), 4))

    for risk in sorted_risks:
        remediation = risk.get('remediation', '')
        if not remediation:
            continue
        action_num += 1
        level = str(risk.get('level', 'unknown')).lower()
        level_fr = LEVEL_TRANSLATIONS.get(level, level.upper())
        p_style = _get_risk_style(level, s)

        # Titre de l'action
        title = risk.get('title', risk.get('description', 'Action requise'))
        story.append(Paragraph(f"<b>{action_num}. [{level_fr}] {_safe_str(title)}</b>", p_style))
        # Remédiation
        story.append(Paragraph(f"{_safe_str(remediation)}", s['remediation']))
        story.append(Spacer(1, 6))

    if action_num == 0:
        story.append(Paragraph("Aucune action prioritaire requise. Votre poste est bien configuré.", s['normal']))

    story.append(Spacer(1, 16))

    # ===== RECOMMANDATIONS GÉNÉRALES =====
    recommendations = ai_report.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Recommandations Générales", s['h1']))
        story.append(Spacer(1, 6))
        for i, rec in enumerate(recommendations, 1):
            if isinstance(rec, dict):
                action = rec.get('action', str(rec))
                command = rec.get('command', '')
                story.append(Paragraph(f"<b>{i}.</b> {_safe_str(action)}", s['normal']))
                if command:
                    story.append(Paragraph(f"<font face='Courier' size='8'>{_safe_str(command)}</font>", s['command']))
            else:
                story.append(Paragraph(f"<b>{i}.</b> {_safe_str(str(rec))}", s['normal']))
            story.append(Spacer(1, 4))

    # ===== PIED DE PAGE =====
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e0')))
    story.append(Spacer(1, 6))
    footer_style = ParagraphStyle('Footer', parent=s['small'], alignment=TA_CENTER, fontSize=7, textColor=colors.HexColor('#a0aec0'))
    story.append(Paragraph(f"Document généré par CyberScan — {now}", footer_style))
    story.append(Paragraph("En cas de doute, contactez votre administrateur réseau.", footer_style))

    doc.build(story)
    return output_path
