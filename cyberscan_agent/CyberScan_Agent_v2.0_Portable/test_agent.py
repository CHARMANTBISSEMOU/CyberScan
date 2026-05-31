#!/usr/bin/env python3
"""
Test de l'exécutable CyberScanAgent.exe
"""

import subprocess
import time
import os

def test_agent_exe():
    """Teste si l'exécutable CyberScanAgent.exe fonctionne."""
    print("🧪 Test de l'exécutable CyberScanAgent.exe...")
    
    exe_path = os.path.join(os.getcwd(), "CyberScanAgent.exe")
    
    if not os.path.exists(exe_path):
        print(f"❌ Fichier non trouvé: {exe_path}")
        return False
    
    try:
        # Lancer l'agent en mode test (vérifier qu'il démarre)
        print(f"📂 Lancement de: {exe_path}")
        
        # Utiliser subprocess pour lancer l'agent en mode silencieux pour le test
        process = subprocess.Popen([exe_path, "--silent"], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 text=True)
        
        # Attendre un peu pour voir s'il démarre
        time.sleep(3)
        
        # Vérifier si le processus est encore en cours (normal s'il cherche un serveur)
        if process.poll() is None:
            print("✅ CyberScanAgent.exe démarré avec succès!")
            print("📡 L'agent recherche le serveur CyberScan...")
            
            # Arrêter le processus proprement
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            
            return True
        else:
            # Récupérer les erreurs
            stdout, stderr = process.communicate()
            print(f"❌ L'agent s'est arrêté avec le code: {process.returncode}")
            if stderr:
                print(f"Erreur: {stderr}")
            if stdout:
                print(f"Sortie: {stdout}")
            return False
            
    except Exception as e:
        print(f"❌ Erreur lors du test: {e}")
        return False

def check_agent_package():
    """Vérifie l'intégrité du package agent."""
    print("\n📦 Vérification du package agent...")
    
    required_files = [
        "CyberScanAgent.exe",
        "README_AGENT.txt"
    ]
    
    missing_files = []
    for file in required_files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"✅ {file} ({size:,} octets)")
        else:
            print(f"❌ {file} - MANQUANT")
            missing_files.append(file)
    
    if not missing_files:
        print("✅ Package agent complet et intact!")
        return True
    else:
        print(f"❌ Fichiers manquants: {missing_files}")
        return False

def main():
    """Fonction principale de test."""
    print("=" * 60)
    print("🚀 TEST DU PACKAGE CYBERSCAN AGENT v2.0")
    print("=" * 60)
    
    # Vérifier l'intégrité
    package_ok = check_agent_package()
    
    if package_ok:
        # Tester l'exécutable
        agent_ok = test_agent_exe()
        
        if agent_ok:
            print("\n" + "=" * 60)
            print("🎉 PACKAGE CYBERSCAN AGENT PRÊT À L'EMPLOI!")
            print("=" * 60)
            print("📋 Instructions de déploiement:")
            print("1. Copiez CyberScanAgent.exe sur la machine cible")
            print("2. Exécutez: CyberScanAgent.exe")
            print("3. Ou en mode silencieux: CyberScanAgent.exe --silent")
            print("4. L'agent se connectera automatiquement au serveur")
            print("=" * 60)
            print("📡 Le serveur CyberScan doit être en cours d'exécution")
            print("🔍 L'agent utilisera mDNS pour découvrir le serveur")
            print("🔐 La communication est chiffrée via WebSocket SSL")
            print("=" * 60)
        else:
            print("\n❌ L'agent présente des problèmes")
    else:
        print("\n❌ Le package agent est incomplet")

if __name__ == "__main__":
    main()
