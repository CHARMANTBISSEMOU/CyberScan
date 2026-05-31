#!/usr/bin/env python3
"""
Test de l'exécutable CyberScan.exe
"""

import subprocess
import time
import os

def test_cyberscan_exe():
    """Teste si l'exécutable CyberScan.exe fonctionne."""
    print("🧪 Test de l'exécutable CyberScan.exe...")
    
    exe_path = os.path.join(os.getcwd(), "CyberScan.exe")
    
    if not os.path.exists(exe_path):
        print(f"❌ Fichier non trouvé: {exe_path}")
        return False
    
    try:
        # Lancer l'exécutable en mode test (vérifier qu'il démarre)
        print(f"📂 Lancement de: {exe_path}")
        
        # Utiliser subprocess pour lancer l'exe
        process = subprocess.Popen([exe_path], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 text=True)
        
        # Attendre un peu pour voir s'il démarre
        time.sleep(2)
        
        # Vérifier si le processus est toujours en cours
        if process.poll() is None:
            print("✅ CyberScan.exe démarré avec succès!")
            print("📊 L'interface graphique devrait être visible")
            
            # Arrêter le processus proprement
            process.terminate()
            process.wait(timeout=5)
            
            return True
        else:
            # Récupérer les erreurs
            stdout, stderr = process.communicate()
            print(f"❌ L'exécutable s'est arrêté avec le code: {process.returncode}")
            if stderr:
                print(f"Erreur: {stderr}")
            if stdout:
                print(f"Sortie: {stdout}")
            return False
            
    except Exception as e:
        print(f"❌ Erreur lors du test: {e}")
        return False

def check_package_integrity():
    """Vérifie l'intégrité du package."""
    print("\n📦 Vérification de l'intégrité du package...")
    
    required_files = [
        "CyberScan.exe",
        "README.txt",
        "cyberscan.db"
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
        print("✅ Package complet et intact!")
        return True
    else:
        print(f"❌ Fichiers manquants: {missing_files}")
        return False

def main():
    """Fonction principale de test."""
    print("=" * 60)
    print("🚀 TEST DU PACKAGE CYBERSCAN v2.0")
    print("=" * 60)
    
    # Vérifier l'intégrité
    integrity_ok = check_package_integrity()
    
    if integrity_ok:
        # Tester l'exécutable
        exe_ok = test_cyberscan_exe()
        
        if exe_ok:
            print("\n" + "=" * 60)
            print("🎉 PACKAGE CYBERSCAN PRÊT À L'EMPLOI!")
            print("=" * 60)
            print("📋 Instructions:")
            print("1. Copiez le dossier dist/ sur la machine cible")
            print("2. Double-cliquez sur CyberScan.exe")
            print("3. L'application démarrera avec l'interface complète")
            print("4. Les fichiers de données seront créés automatiquement")
            print("=" * 60)
        else:
            print("\n❌ L'exécutable présente des problèmes")
    else:
        print("\n❌ Le package est incomplet")

if __name__ == "__main__":
    main()
