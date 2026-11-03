; zainVPN Windows installer (Inno Setup 6.6+, for WizardStyle "modern dynamic"). Normally compiled by build.ps1.
;
; Defines (override with ISCC /DName=value):
;   AppVersion   numeric version, x.y[.z[.w]]
;   DefServer, DefNetwork, DefPassword, DefName
;                defaults for the "Join your group" page. They are pasted into
;                Pascal single-quoted strings, so they must arrive escaped:
;                ' doubled, and " written as '#34' (ISCC's command line cannot
;                carry a literal double quote).
;   SourceDir    folder holding zainvpn.exe and wintun.dll
;   OutputDir    where zainVPN-Setup.exe is written
;
; Unattended install: zainVPN-Setup.exe /VERYSILENT /SERVER=host[:port]
;   /NETWORK=name /PASSWORD=secret [/NAME=nickname]
; These override the defines, but an existing %ProgramData%\zainVPN\config.json
; (upgrade) is always kept as is. Values left empty can be filled in later in
; the local dashboard; the service starts anyway and waits for them.

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef DefServer
  #define DefServer ""
#endif
#ifndef DefNetwork
  #define DefNetwork ""
#endif
#ifndef DefPassword
  #define DefPassword ""
#endif
#ifndef DefName
  #define DefName ""
#endif
#ifndef SourceDir
  #define SourceDir "..\build"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#define UIURL "http://127.0.0.1:7779/"

[Setup]
AppId={{F28EC8D3-7A90-4F4C-B6CC-7DEBF99719CC}
AppName=zainVPN
AppVersion={#AppVersion}
AppPublisher=zainVPN
VersionInfoVersion={#AppVersion}
VersionInfoDescription=zainVPN Setup
DefaultDirName={autopf}\zainVPN
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
WizardStyle=modern dynamic
Compression=lzma2/ultra
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename=zainVPN-Setup
UninstallDisplayName=zainVPN
UninstallDisplayIcon={app}\zainvpn.ico
SetupIconFile=zainvpn.ico
; We stop our own service in PrepareToInstall.
CloseApplications=no
SetupLogging=yes

[Messages]
FinishedHeadingLabel=zainVPN is ready
FinishedLabel=zainVPN is running and will start automatically with Windows.%n%nOpen the zainVPN shortcut any time to see who's online.
FinishedLabelNoIcons=zainVPN is running and will start automatically with Windows.%n%nOpen the zainVPN shortcut any time to see who's online.

[Tasks]
Name: desktopicon; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\zainvpn.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\third_party\wintun\LICENSE.txt"; DestDir: "{app}"; DestName: "wintun-LICENSE.txt"; Flags: ignoreversion
; Logo for the shortcuts and Apps list (made by installer/mkicon.go).
Source: "zainvpn.ico"; DestDir: "{app}"; Flags: ignoreversion

[INI]
Filename: "{autoprograms}\zainVPN.url"; Section: "InternetShortcut"; Key: "URL"; String: "{#UIURL}"
Filename: "{autoprograms}\zainVPN.url"; Section: "InternetShortcut"; Key: "IconFile"; String: "{app}\zainvpn.ico"
Filename: "{autoprograms}\zainVPN.url"; Section: "InternetShortcut"; Key: "IconIndex"; String: "0"
Filename: "{autodesktop}\zainVPN.url"; Section: "InternetShortcut"; Key: "URL"; String: "{#UIURL}"; Tasks: desktopicon
Filename: "{autodesktop}\zainVPN.url"; Section: "InternetShortcut"; Key: "IconFile"; String: "{app}\zainvpn.ico"; Tasks: desktopicon
Filename: "{autodesktop}\zainVPN.url"; Section: "InternetShortcut"; Key: "IconIndex"; String: "0"; Tasks: desktopicon

[Run]
Filename: "{#UIURL}"; Description: "Open zainVPN"; Flags: postinstall shellexec skipifsilent nowait; Check: ServiceStarted

[UninstallRun]
Filename: "{app}\zainvpn.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "zainvpnUninstall"

[UninstallDelete]
Type: files; Name: "{autoprograms}\zainVPN.url"
Type: files; Name: "{autodesktop}\zainVPN.url"
; Backstop: "zainvpn.exe uninstall" already removes it.
Type: filesandordirs; Name: "{commonappdata}\zainVPN"

[Code]
var
  JoinPage: TInputQueryWizardPage;
  ServiceOK: Boolean;

function DataDir: String;
begin
  Result := ExpandConstant('{commonappdata}\zainVPN');
end;

function ConfigPath: String;
begin
  Result := DataDir + '\config.json';
end;

function ServiceStarted: Boolean;
begin
  Result := ServiceOK;
end;

{ CmdParam returns the value of /Name=value (or -Name=value) on Setup's
  command line, or Default when absent. }
function CmdParam(const Name, Default: String): String;
var
  I: Integer;
  P, Prefix: String;
begin
  Result := Default;
  Prefix := Name + '=';
  for I := 1 to ParamCount do begin
    P := ParamStr(I);
    if ((Copy(P, 1, 1) = '/') or (Copy(P, 1, 1) = '-')) and
       (CompareText(Copy(P, 2, Length(Prefix)), Prefix) = 0) then
      Result := Copy(P, Length(Prefix) + 2, MaxInt);
  end;
end;

function JSONString(const S: String): String;
var
  I: Integer;
  C: Char;
begin
  Result := '"';
  for I := 1 to Length(S) do begin
    C := S[I];
    if (C = '"') or (C = '\') then
      Result := Result + '\' + C
    else if Ord(C) < 32 then
      Result := Result + Format('\u%.4x', [Ord(C)])
    else
      Result := Result + C;
  end;
  Result := Result + '"';
end;

procedure InitializeWizard;
var
  Name: String;
begin
  Name := '{#DefName}';
  if Name = '' then
    Name := GetComputerNameString;

  JoinPage := CreateInputQueryPage(wpSelectDir, 'Join your group',
    'Your friend may have filled these in already ' + #$2014 + ' just choose a nickname.',
    'zainVPN puts this PC on a private network with your friends, so LAN games can find each other. ' +
    'If anything below is blank, ask the friend who sent you this installer.');
  JoinPage.Add('Nic&kname:', False);
  JoinPage.Add('&Coordinator address:', False);
  JoinPage.Add('Network na&me:', False);
  JoinPage.Add('Network &password:', True);
  { Same limits as zainvpn.exe's config validation. }
  JoinPage.Edits[0].MaxLength := 32;
  JoinPage.Edits[2].MaxLength := 64;

  JoinPage.Values[0] := CmdParam('NAME', Name);
  JoinPage.Values[1] := CmdParam('SERVER', '{#DefServer}');
  JoinPage.Values[2] := CmdParam('NETWORK', '{#DefNetwork}');
  JoinPage.Values[3] := CmdParam('PASSWORD', '{#DefPassword}');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  { An upgrade keeps the existing settings. }
  Result := (PageID = JoinPage.ID) and FileExists(ConfigPath);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  I: Integer;
begin
  Result := True;
  { Silent installs take what they were given; settings can be fixed in the local UI. }
  if (CurPageID <> JoinPage.ID) or WizardSilent then
    Exit;
  for I := 0 to 3 do
    if Trim(JoinPage.Values[I]) = '' then begin
      MsgBox('Please fill in every field. If you don''t know them, ask the friend who sent you this installer.',
        mbError, MB_OK);
      WizardForm.ActiveControl := JoinPage.Edits[I];
      Result := False;
      Exit;
    end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Exe: String;
  Code: Integer;
begin
  Result := '';
  { Stop the running service so its files aren't locked during an upgrade. }
  Exe := ExpandConstant('{app}\zainvpn.exe');
  if FileExists(Exe) then
    if Exec(Exe, 'stop', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) then
      Log(Format('zainvpn.exe stop exited with code %d', [Code]))
    else
      Log('Could not run zainvpn.exe stop: ' + SysErrorMessage(Code));
end;

procedure WriteConfig;
var
  Name: String;
  Lines: TArrayOfString;
begin
  if FileExists(ConfigPath) then begin
    Log('Keeping existing ' + ConfigPath);
    Exit;
  end;
  Name := Trim(JoinPage.Values[0]);
  if Name = '' then
    Name := GetComputerNameString;
  SetArrayLength(Lines, 6);
  Lines[0] := '{';
  Lines[1] := '  "server": ' + JSONString(Trim(JoinPage.Values[1])) + ',';
  Lines[2] := '  "network": ' + JSONString(Trim(JoinPage.Values[2])) + ',';
  Lines[3] := '  "password": ' + JSONString(JoinPage.Values[3]) + ',';
  Lines[4] := '  "name": ' + JSONString(Name);
  Lines[5] := '}';
  if ForceDirectories(DataDir) and SaveStringsToUTF8FileWithoutBOM(ConfigPath, Lines, False) then
    Log('Wrote ' + ConfigPath)
  else
    SuppressibleMsgBox('Could not write ' + ConfigPath + '.', mbError, MB_OK, IDOK);
end;

procedure InstallService;
var
  Code: Integer;
  Reason: String;
begin
  WizardForm.StatusLabel.Caption := 'Starting the zainVPN service...';
  if Exec(ExpandConstant('{app}\zainvpn.exe'), 'install', ExpandConstant('{app}'),
      SW_HIDE, ewWaitUntilTerminated, Code) then begin
    if Code = 0 then begin
      ServiceOK := True;
      Exit;
    end;
    Reason := Format('exit code %d', [Code]);
  end else
    Reason := SysErrorMessage(Code);
  Log('zainvpn.exe install failed: ' + Reason);
  SuppressibleMsgBox('zainVPN was installed, but its background service could not be set up (' + Reason + ').' + #13#10#13#10 +
    'Details are in ' + DataDir + '\zainvpn.log', mbError, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    WriteConfig;
    InstallService;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and not ServiceOK then begin
    WizardForm.FinishedHeadingLabel.Caption := 'zainVPN needs attention';
    WizardForm.FinishedLabel.Caption := 'zainVPN was installed, but its service did not start. ' +
      'Details are in ' + DataDir + '\zainvpn.log. Restarting the PC or running this installer again may help.';
    WizardForm.FinishedLabel.AdjustHeight;
  end;
end;
