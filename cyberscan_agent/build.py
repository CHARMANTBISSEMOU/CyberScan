import PyInstaller.__main__
import os

def build_agent():
    """
    Compile l'agent CyberScan en un exécutable Windows autonome (.exe).
    """
    print("Début de la compilation de l'agent CyberScan avec PyInstaller...")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    agent_script = os.path.join(current_dir, "agent.py")
    
    if not os.path.exists(agent_script):
        print(f"Erreur : le fichier {agent_script} est introuvable.")
        return

    PyInstaller.__main__.run([
        agent_script,
        '--name=CyberScanAgent',
        '--onefile',       # Package into a single executable
        '--noconsole',     # Do not show a command prompt window (silent background execution)
        '--clean',         # Clean PyInstaller cache
        '--uac-admin',     # Request Administrator privileges when executed (required for Security Event Logs)
        f'--icon=C:\\Users\\EDITH-PARKERT\\Desktop\\COURS KEYCE\\Semestre II\\Projet tuteure4\\Medias\\logo.ico',
        f'--paths={current_dir}',
        '--hidden-import=win_scanner',
        '--hidden-import=activity_logger',
        '--hidden-import=port_scanner',
        '--hidden-import=integrity_check',
        '--hidden-import=log_analyzer',
        '--hidden-import=psutil',
        f'--workpath={os.path.join(current_dir, "build")}',
        f'--distpath={os.path.join(current_dir, "dist")}',
        f'--specpath={current_dir}',
    ])
    
    print("\nCompilation terminée !")
    print("L'exécutable se trouve dans le dossier 'dist/'.")

if __name__ == "__main__":
    build_agent()
