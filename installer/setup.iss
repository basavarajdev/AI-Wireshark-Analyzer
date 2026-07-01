; ──────────────────────────────────────────────────────────────────────────────
; AI-Wireshark Analyzer — Inno Setup Installer Script
; ──────────────────────────────────────────────────────────────────────────────
; This creates a professional Windows installer (.exe) with:
;   - Setup wizard (license, destination, components)
;   - Start Menu shortcuts
;   - Desktop shortcut (optional)
;   - File association for .pcap/.pcapng (optional)
;   - Uninstaller in Add/Remove Programs
;
; Prerequisites:
;   1. Build the app with PyInstaller first (see build_installer.bat)
;   2. Install Inno Setup from https://jrsoftware.org/isinfo.php
;   3. Compile this .iss file with Inno Setup Compiler
;
; Output: installer/output/AI-Wireshark-Analyzer-Setup-x64.exe
; ──────────────────────────────────────────────────────────────────────────────

#define MyAppName "AI-Wireshark Analyzer"
#define MyAppVersion "1.5.0"
#define MyAppPublisher "AI-Wireshark Project"
#define MyAppURL "https://github.com/ai-wireshark-analyzer"
#define MyAppExeName "AI-Wireshark-Analyzer.exe"
#define MyAppAssocName "Packet Capture File"
#define MyAppAssocExt1 ".pcap"
#define MyAppAssocExt2 ".pcapng"
#define MyAppAssocKey "AI-Wireshark.PacketCapture"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={userappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
; License file (use project LICENSE)
LicenseFile=..\LICENSE
; Output settings
OutputDir=output
OutputBaseFilename=AI-Wireshark-Analyzer-Setup-x64
; Installer appearance
SetupIconFile=app_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
WizardSizePercent=120
; Compression
Compression=lzma2/ultra64
SolidCompression=yes
; Require 64-bit Windows
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Privileges
PrivilegesRequired=lowest
; Minimum Windows version (Windows 10+)
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "fileassoc"; Description: "Associate .pcap and .pcapng files with {#MyAppName}"; GroupDescription: "File Associations:"

[Files]
; Main application files
Source: "..\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\setup.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\QUICKSTART.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\launch-gui-windows.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\launch-cli-windows.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\installer\app_icon.ico"; DestDir: "{app}\installer"; Flags: ignoreversion
; Ensure results directory exists
Source: "..\results\.gitkeep"; DestDir: "{app}\results"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}"; Filename: "{app}\launch-gui-windows.bat"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; Desktop (optional)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\launch-gui-windows.bat"; Tasks: desktopicon

[Registry]
; File associations (optional)
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}"; ValueType: string; ValueName: ""; ValueData: "{#MyAppAssocName}"; Flags: uninsdeletekey; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocExt1}\OpenWithProgids"; ValueType: string; ValueName: "{#MyAppAssocKey}"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassoc
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocExt2}\OpenWithProgids"; ValueType: string; ValueName: "{#MyAppAssocKey}"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassoc

[Run]
; Launch app after install (optional)
Filename: "{app}\launch-gui-windows.bat"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up generated files on uninstall
Type: filesandordirs; Name: "{app}\results"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\__pycache__"

[Code]
// Check if tshark/Wireshark is installed
function IsTsharkInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('cmd.exe', '/c where tshark', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpReady then
  begin
    if not IsTsharkInstalled() then
    begin
      MsgBox('WARNING: Wireshark/tshark was not found on your system.' + #13#10 + #13#10 +
             'AI-Wireshark Analyzer requires tshark for packet analysis.' + #13#10 +
             'Please install Wireshark from https://www.wireshark.org/download.html' + #13#10 + #13#10 +
             'You can continue the installation, but the app will not function without tshark.',
             mbInformation, MB_OK);
    end;
  end;
end;
