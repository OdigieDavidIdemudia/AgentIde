; AgentIDE installer — Pro (Inno Setup 6/7)
;
; Silent/automated install example:
;   AgentIDE_Installer.exe /VERYSILENT /SUPPRESSMSGBOXES ^
;     /DASHBOARDURL="wss://192.168.1.168:8443" /AGENTTOKEN="<token>" ^
;     /CERTPIN="" /ALLOWREBOOT="no"
;
; The dashboard URL may be a comma-separated list of addresses to try in order,
; e.g. /DASHBOARDURL="wss://10.0.0.5:8443,wss://192.168.1.168:8443"

; AppVersion is supplied by build_pro.bat as /DAppVersion=<x.y.z>, read from
; version.json — the same source the agent binary and MSI use. That keeps the
; three installers from drifting apart, which previously let a v0.1.0 setup
; binary ship alongside a v0.4.0 agent.
#ifndef AppVersion
  #error AppVersion is not defined - build via build_pro.bat (or pass /DAppVersion=x.y.z)
#endif

[Setup]
AppName=AgentIDE
; Version comes from version.json (via /DAppVersion passed by build_pro.bat) so
; the Inno installer can never drift from the agent binary or the MSI.
AppVersion={#AppVersion}
AppPublisher=AgentIDE Project
DefaultDirName={commonpf}\AgentIDE
DefaultGroupName=AgentIDE
OutputDir=msi_output
OutputBaseFilename=AgentIDE_Installer_v{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
DisableProgramGroupPage=yes
AlwaysRestart=no
RestartIfNeededByRun=no
WizardStyle=modern
UninstallDisplayIcon={app}\agentide.exe
UninstallDisplayName=AgentIDE {#AppVersion}
AppCopyright=Copyright (C) 2024 AgentIDE Project
AppVerName=AgentIDE {#AppVersion}

[Files]
Source: "agentide.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "agentide-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\AgentIDE Dashboard"; Filename: "https://localhost:8443"; IconFilename: "{app}\agentide.exe"; WorkingDir: "{app}"
Name: "{group}\AgentIDE Tray"; Filename: "{app}\agentide-tray.exe"; IconFilename: "{app}\agentide-tray.exe"; WorkingDir: "{app}"
Name: "{group}\Uninstall AgentIDE"; Filename: "{uninstallexe}"; IconFilename: "{app}\agentide.exe"

[Run]
; Install the service — writes config.json with URL, token, cert pin, allow_reboot.
; The optional --allow-reboot argument is appended only when the user opted in.
Filename: "{app}\agentide.exe"; Parameters: "--install --dashboard ""{code:GetDashboardUrl}"" --token ""{code:GetAgentToken}"" --cert-pin ""{code:GetCertPin}""{code:GetAllowRebootArg}"; Flags: runhidden waituntilterminated; AfterInstall: VerifyDashboardConnection; StatusMsg: "Installing and starting the AgentIDE service..."

; Start the tray immediately so the notification-area icon is present the moment
; installation finishes, rather than only after the operator signs out and back
; in. Deliberately NOT waituntilterminated: the tray runs for as long as the
; session lasts, and waiting on it would hang the installer forever.
;
; This launches in whatever session runs the installer. If that is session 0 —
; an unattended silent install from another machine — no tray icon can appear,
; because the notification area belongs to the interactive desktop. In that
; case the icon shows up when the endpoint's own user next signs in.
Filename: "{app}\agentide-tray.exe"; Description: "Start the AgentIde tray icon"; Flags: runhidden

[Registry]
; Per-user auto-start is registered by the tray itself on first run, not here.
;
; Writing HKCU from the installer targets the *elevating administrator's* hive,
; so any other operator signing in afterwards never got the icon. The tray
; registers into the Run key of whichever account actually executes it, which
; is what "the icon is always there" requires. The [Run] entry above starts it
; once, which chains into that registration.

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop AgentIde"; RunOnceId: "StopSvc"; Flags: runhidden waituntilterminated; StatusMsg: "Stopping AgentIDE service..."
Filename: "{app}\agentide.exe"; Parameters: "--uninstall"; RunOnceId: "UninstallSvc"; Flags: runhidden waituntilterminated; StatusMsg: "Removing AgentIDE service..."

[Code]
var
  DashboardPage: TInputQueryWizardPage;
  TokenPage: TInputQueryWizardPage;
  CertPinPage: TInputQueryWizardPage;
  AllowRebootPage: TInputQueryWizardPage;

function GetDashboardUrl(Param: string): string;
begin
  Result := Trim(DashboardPage.Values[0]);
end;

function GetAgentToken(Param: string): string;
begin
  Result := Trim(TokenPage.Values[0]);
end;

function GetCertPin(Param: string): string;
begin
  Result := Trim(CertPinPage.Values[0]);
end;

// Returns "--allow-reboot" only when the operator opted in. Passing
// --allow-reboot with a value would always turn it on (Go bool flags).
function GetAllowRebootArg(Param: string): string;
begin
  if CompareText(Trim(AllowRebootPage.Values[0]), 'yes') = 0 then
    Result := ' --allow-reboot'
  else
    Result := '';
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel1.Caption := 'Welcome to the AgentIDE Setup Wizard';
  WizardForm.WelcomeLabel2.Caption := 'This will install the AgentIDE EDR/XDR Assessment Agent.'#13#10#13#10'It is recommended that you close other applications first.';

  DashboardPage := CreateInputQueryPage(wpSelectDir,
    'Dashboard connection',
    'Where should this agent report?',
    'Enter the dashboard address. You can list several comma-separated addresses to try in order.');
  DashboardPage.Add('Dashboard URL:', False);
  DashboardPage.Values[0] := Trim(ExpandConstant('{param:DASHBOARDURL}'));

  TokenPage := CreateInputQueryPage(DashboardPage.ID,
    'Agent authentication',
    'Enter the agent token.',
    'This must match AGENT_TOKEN in the dashboard .env file.');
  TokenPage.Add('Token:', False);
  TokenPage.Values[0] := Trim(ExpandConstant('{param:AGENTTOKEN}'));

  CertPinPage := CreateInputQueryPage(TokenPage.ID,
    'Certificate pinning (optional)',
    'Paste the dashboard certificate pin, if you pinned one.',
    'Hex SHA-256 of the dashboard cert public key. Leave blank to trust the self-signed cert.');
  CertPinPage.Add('Cert pin (optional):', False);
  CertPinPage.Values[0] := Trim(ExpandConstant('{param:CERTPIN}'));

  AllowRebootPage := CreateInputQueryPage(CertPinPage.ID,
    'Reboot testing',
    'Allow reboot during testing?',
    'Only enable on systems where an autonomous reboot is acceptable.');
  AllowRebootPage.Add('Allow reboot (yes/no):', False);
  AllowRebootPage.Values[0] := Trim(ExpandConstant('{param:ALLOWREBOOT}'));
  if AllowRebootPage.Values[0] = '' then
    AllowRebootPage.Values[0] := 'no';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  url: string;
begin
  Result := True;
  if CurPageID = DashboardPage.ID then
  begin
    url := LowerCase(GetDashboardUrl(''));
    if url = '' then
    begin
      MsgBox('Enter the dashboard address, for example wss://192.168.1.168:8443', mbError, MB_OK);
      Result := False;
    end
    else if (Pos('ws://', url) <> 1) and (Pos('wss://', url) <> 1) then
    begin
      MsgBox('The dashboard address must start with ws:// or wss://', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = TokenPage.ID then
  begin
    if GetAgentToken('') = '' then
    begin
      MsgBox('Enter the agent token from the dashboard (.env AGENT_TOKEN).', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure VerifyDashboardConnection;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{app}\agentide.exe'),
              '-check -dashboard "' + GetDashboardUrl('') + '" -token "' + GetAgentToken('') + '"',
              ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    MsgBox('The agent was installed but the connectivity check could not be run.', mbError, MB_OK);
    Exit;
  end;

  if ResultCode = 0 then
    MsgBox('AgentIDE is installed and reporting to:'#13#10 + GetDashboardUrl(''), mbInformation, MB_OK)
  else
    MsgBox('AgentIDE was installed but could NOT reach the dashboard at:'#13#10 +
           GetDashboardUrl('') + #13#10#13#10 +
           'Check the address/token and the network, then test with:'#13#10 +
           'agentide.exe -check -dashboard <url> -token <token>',
           mbError, MB_OK);
end;
