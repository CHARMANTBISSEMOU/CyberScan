; =====================================================================
; Script Inno Setup - CyberScan Installer v2.1
; Génère un setup professionnel pour CyberScan Admin + Agent
; =====================================================================

#define MyAppName "CyberScan"
#define MyAppVersion "2.1"
#define MyAppPublisher "Projet Tuteuré - KEYCE Informatique"
#define MyAppURL "https://github.com/CHARMANTBISSEMOU/CyberScan"
#define MyAppExeName "CyberScan.exe"
#define MyAgentExeName "CyberScanAgent.exe"
#define MyIconPath "C:\Users\EDITH-PARKERT\Desktop\COURS KEYCE\Semestre II\Projet tuteure4\Medias\logo.ico"
#define AdminExe "C:\Users\EDITH-PARKERT\Desktop\COURS KEYCE\Semestre II\Projet tuteure4\cyberscan\cyberscan_admin\dist\CyberScanAdmin.exe"
#define AgentExe "C:\Users\EDITH-PARKERT\Desktop\COURS KEYCE\Semestre II\Projet tuteure4\cyberscan\cyberscan_agent\dist\CyberScanAgent.exe"
#define DBFile "C:\Users\EDITH-PARKERT\Desktop\COURS KEYCE\Semestre II\Projet tuteure4\cyberscan\CyberScan_Final_v2.1_Simple\cyberscan.db"
#define CertsDir "C:\Users\EDITH-PARKERT\Desktop\COURS KEYCE\Semestre II\Projet tuteure4\cyberscan\CyberScan_Final_v2.1_Simple\certs"
#define OutputDir "C:\Users\EDITH-PARKERT\Desktop\COURS KEYCE\Semestre II\Projet tuteure4\cyberscan\Setup"

[Setup]
AppId={{B4C1A2D3-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\CyberScan
DefaultGroupName={#MyAppName}
AllowNoIcons=no
LicenseFile=
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=CyberScan_Setup_Final
SetupIconFile={#MyIconPath}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardResizable=no
ShowLanguageDialog=no

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon_admin"; Description: "Créer un raccourci Bureau pour CyberScan Admin"; GroupDescription: "Raccourcis supplémentaires :"; Flags: unchecked
Name: "desktopicon_agent"; Description: "Créer un raccourci Bureau pour CyberScan Agent"; GroupDescription: "Raccourcis supplémentaires :"; Flags: unchecked
Name: "startup_agent"; Description: "Lancer l'agent CyberScan automatiquement au démarrage de Windows (recommandé)"; GroupDescription: "Options de démarrage :"; Flags: checkedonce

[Files]
; Application Admin
Source: "{#AdminExe}"; DestDir: "{app}"; DestName: "CyberScan.exe"; Flags: ignoreversion
; Agent silencieux
Source: "{#AgentExe}"; DestDir: "{app}"; DestName: "CyberScanAgent.exe"; Flags: ignoreversion
; Base de données initiale (déployée dans AppData pour avoir les droits d'écriture)
Source: "{#DBFile}"; DestDir: "{userappdata}\CyberScan"; DestName: "cyberscan.db"; Flags: onlyifdoesntexist
; Certificats SSL pour le serveur WebSocket
Source: "{#CertsDir}\*"; DestDir: "{app}\certs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Menu Démarrer
Name: "{group}\CyberScan Admin"; Filename: "{app}\CyberScan.exe"; IconFilename: "{app}\CyberScan.exe"
Name: "{group}\CyberScan Agent (Manuel)"; Filename: "{app}\CyberScanAgent.exe"; IconFilename: "{app}\CyberScanAgent.exe"
Name: "{group}\Désinstaller CyberScan"; Filename: "{uninstallexe}"

; Raccourcis Bureau (optionnels)
Name: "{autodesktop}\CyberScan Admin"; Filename: "{app}\CyberScan.exe"; IconFilename: "{app}\CyberScan.exe"; Tasks: desktopicon_admin
Name: "{autodesktop}\CyberScan Agent"; Filename: "{app}\CyberScanAgent.exe"; IconFilename: "{app}\CyberScanAgent.exe"; Tasks: desktopicon_agent

[Registry]
; Démarrage automatique de l'agent au démarrage de Windows
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CyberScanAgent"; ValueData: """{app}\CyberScanAgent.exe"""; Flags: uninsdeletevalue; Tasks: startup_agent

[Run]
; Lancer l'agent en arrière-plan après installation (silencieux)
Filename: "{app}\CyberScanAgent.exe"; Description: "Démarrer l'agent CyberScan maintenant"; Flags: shellexec nowait postinstall skipifsilent; Tasks: startup_agent
; Proposer d'ouvrir l'application Admin après installation
Filename: "{app}\CyberScan.exe"; Description: "Lancer CyberScan Admin maintenant"; Flags: shellexec nowait postinstall skipifsilent

[UninstallRun]
; Arrêter l'agent avant désinstallation
Filename: "taskkill.exe"; Parameters: "/F /IM CyberScanAgent.exe"; Flags: runhidden

[Code]
procedure InitializeWizard;
var
  WelcomeText: string;
begin
  WelcomeText := 'CyberScan est une solution de supervision de cybersecurite autonome pour les TPE/PME.';
  WelcomeText := WelcomeText + #13#10 + #13#10;
  WelcomeText := WelcomeText + 'Ce programme va installer :' + #13#10;
  WelcomeText := WelcomeText + '  - CyberScan Admin : Interface de gestion centralisee' + #13#10;
  WelcomeText := WelcomeText + '  - CyberScan Agent : Agent de surveillance silencieux' + #13#10;
  WelcomeText := WelcomeText + #13#10;
  WelcomeText := WelcomeText + 'Il est recommande de fermer toutes vos applications avant de continuer.' + #13#10;
  WelcomeText := WelcomeText + #13#10;
  WelcomeText := WelcomeText + 'Cliquez sur Suivant pour continuer.';
  WizardForm.WelcomeLabel2.Caption := WelcomeText;
end;
