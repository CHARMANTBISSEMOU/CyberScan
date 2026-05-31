import PyInstaller.__main__
import os
import shutil

def build_admin():
    """
    Compile l'application CyberScan Admin en un exécutable Windows.
    """
    print("Début de la compilation de l'App Admin avec PyInstaller...")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    app_script = os.path.join(current_dir, "app.py")
    
    if not os.path.exists(app_script):
        print(f"Erreur : le fichier {app_script} est introuvable.")
        return

    # On utilise --windowed pour cacher la console noire en arrière-plan d'une app GUI
    # On ajoute le dossier certs pour que le serveur HTTPS/WSS puisse se lancer
    certs_dir = os.path.join(os.path.dirname(current_dir), "certs")
    
    PyInstaller.__main__.run([
        app_script,
        '--name=CyberScanAdmin',
        '--onefile',
        '--windowed',
        '--clean',
        f'--paths={current_dir}',
        f'--add-data={certs_dir};certs',
        '--hidden-import=ia_analyzer',
        '--hidden-import=database',
        '--hidden-import=network_scanner_fixed',
        '--hidden-import=traffic_monitor_simple',
        '--hidden-import=server',
        '--hidden-import=pdf_generator',
        '--hidden-import=packet_capture',
        f'--workpath={os.path.join(current_dir, "build")}',
        f'--distpath={os.path.join(current_dir, "dist")}',
        f'--specpath={current_dir}'
    ])
    
    print("\nCompilation terminée !")
    print("L'exécutable CyberScanAdmin.exe se trouve dans le dossier 'cyberscan_admin/dist/'.")

if __name__ == "__main__":
    build_admin()
