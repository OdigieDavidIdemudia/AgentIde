[Setup]
AppName=AgentIDE
AppVersion=0.1.0
AppPublisher=AgentIDE Project
DefaultDirName={commonpf}\AgentIDE
DefaultGroupName=AgentIDE
OutputBaseFilename=AgentIDE_Installer
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
OutputDir=.\
DisableProgramGroupPage=yes
AlwaysRestart=yes

[Files]
Source: "agentide.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Install the service — also writes config.json with the dashboard URL,
; agent token, and cert pin next to the exe
Filename: "{app}\agentide.exe"; Parameters: "--install --dashboard ""{code:GetDashboardUrl}"" --token ""{code:GetAgentToken}"""; Flags: runhidden waituntilterminated

[UninstallRun]
; Stop the service
Filename: "sc.exe"; Parameters: "stop AgentIde"; RunOnceId: "StopSvc"; Flags: runhidden waituntilterminated
; Uninstall the service
Filename: "{app}\agentide.exe"; Parameters: "--uninstall"; RunOnceId: "UninstallSvc"; Flags: runhidden waituntilterminated

[Code]
var
  DashboardPage: TInputQueryWizardPage;
  TokenPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  DashboardPage := CreateInputQueryPage(wpSelectDir,
    'Dashboard Configuration',
    'Where should the agent report to?',
    'Please specify the AgentIDE dashboard URL (e.g., wss://192.168.1.10:8443).');

  DashboardPage.Add('Dashboard URL:', False);
  DashboardPage.Values[0] := 'wss://localhost:8443/agent';

  TokenPage := CreateInputQueryPage(DashboardPage.ID,
    'Agent Authentication',
    'Enter the agent token shown on the dashboard (AGENT_TOKEN).',
    'The agent uses this token to authenticate to the dashboard.');

  TokenPage.Add('Agent token:', True);
  TokenPage.Values[0] := '';
end;

function GetDashboardUrl(Param: String): String;
begin
  Result := DashboardPage.Values[0];
end;

function GetAgentToken(Param: String): String;
begin
  Result := TokenPage.Values[0];
end;
