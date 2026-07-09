; Inno Setup script — builds HDM-Dashboard-Setup.exe (a proper Windows installer)
; Installs the app to Program Files with Start-menu and optional desktop shortcuts.

[Setup]
AppName=Health Data Matrics Dashboard
AppVersion=1.0.0
AppPublisher=Health Data Matrics
DefaultDirName={autopf}\Health Data Matrics
DefaultGroupName=Health Data Matrics
DisableProgramGroupPage=yes
OutputDir=installer_out
OutputBaseFilename=HDM-Dashboard-Setup
SetupIconFile=hdm_logo.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\HDM-Dashboard.exe

[Files]
Source: "dist\HDM-Dashboard.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\HDM Dashboard"; Filename: "{app}\HDM-Dashboard.exe"
Name: "{commondesktop}\HDM Dashboard"; Filename: "{app}\HDM-Dashboard.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\HDM-Dashboard.exe"; Description: "Launch HDM Dashboard now"; Flags: nowait postinstall skipifsilent
