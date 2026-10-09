; AgentIDE installer (Inno Setup 6/7)
;
; Silent/automated install example:
;   AgentIDE_Setup.exe /VERYSILENT /SUPPRESSMSGBOXES ^
;     /DASHBOARDURL="wss://192.168.1.168:8443" /AGENTTOKEN="<token>"
;
; The dashboard URL may be a comma-separated list of addresses to try in order,
; e.g. /DASHBOARDURL="wss://10.0.0.5:8443,wss://192.168.1.168:8443"

[Setup]
AppName=AgentIDE
AppVersion=0.4.0
AppPublisher=AgentIDE Project
DefaultDirName={commonpf}\AgentIDE
DisableProgramGroupPage=yes
OutputDir=msi_output
OutputBaseFilename=AgentIDE_Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern
UninstallDisplayIcon={app}\agentide.exe

[Files]
Source: "agentide.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Install the service. AfterInstall runs a connectivity check so an unreachable
; dashboard or bad token is surfaced immediately instead of silently failing.
Filename: "{app}\agentide.exe"; Parameters: "--install --dashboard ""{code:GetDashboardUrl}"" --token ""{code:GetAgentToken}"""; Flags: runhidden waituntilterminated; AfterInstall: VerifyDashboardConnection; StatusMsg: "Installing and starting the AgentIDE service..."

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop AgentIde"; RunOnceId: "StopSvc"; Flags: runhidden waituntilterminated; StatusMsg: "Stopping AgentIDE service..."
Filename: "{app}\agentide.exe"; Parameters: "--uninstall"; RunOnceId: "UninstallSvc"; Flags: runhidden waituntilterminated; StatusMsg: "Removing AgentIDE service..."

[Code]
var
  DashboardPage: TInputQueryWizardPage;
  TokenPage: TInputQueryWizardPage;

function GetDashboardUrl(Param: string): string;
begin
  Result := Trim(DashboardPage.Values[0]);
end;

function GetAgentToken(Param: string): string;
begin
  Result := Trim(TokenPage.Values[0]);
end;

procedure InitializeWizard;
begin
  DashboardPage := CreateInputQueryPage(wpSelectDir,
    'Dashboard connection',
    'Where should this agent report?',
    'Enter the dashboard address. You may list several comma-separated addresses to try in order.');
  DashboardPage.Add('Dashboard URL:', False);
  DashboardPage.Values[0] := Trim(ExpandConstant('{param:DASHBOARDURL}'));

  TokenPage := CreateInputQueryPage(DashboardPage.ID,
    'Agent authentication',
    'Enter the agent token.',
    'This must match AGENT_TOKEN in the dashboard .env file.');
  TokenPage.Add('Token:', False);
  TokenPage.Values[0] := Trim(ExpandConstant('{param:AGENTTOKEN}'));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = DashboardPage.ID then
  begin
    if GetDashboardUrl('') = '' then
    begin
      MsgBox('Enter the dashboard address, for example wss://192.168.1.168:8443', mbError, MB_OK);
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

// Called by the [Run] entry after the service is installed.
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
