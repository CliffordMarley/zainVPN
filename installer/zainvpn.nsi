; zainVPN installer (NSIS 3.08+). Builds on Windows and natively on Linux:
;   makensis -DVERSION=0.2.0 -DSERVER=203.0.113.10 -DSRC=..\build -DOUT=..\dist\zainVPN-Setup.exe zainvpn.nsi
; Paths use backslashes: Windows makensis needs them and Linux makensis converts them.
; SRC must hold zainvpn.exe, zainvpn-app.exe and wintun.dll. The installer only
; contains the coordinator address; friends join networks with invite codes.
; Silent install: zainVPN-Setup.exe /S [/SERVER=host[:port]] [/NAME=nick] [/INVITE=code]

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
!include "WordFunc.nsh"

!ifndef VERSION
  !define VERSION "0.1.0"
!endif
!ifndef SERVER
  !define SERVER ""
!endif
!ifndef SRC
  !define SRC "..\build"
!endif
!ifndef OUT
  !define OUT "..\dist\zainVPN-Setup.exe"
!endif

!define APP "zainVPN"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\zainVPN"
!define CONFIG "$COMMONPROGRAMDATA\zainVPN\config.json"

Name "${APP}"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\zainVPN"
BrandingText "zainVPN ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "FileDescription" "zainVPN Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "zainVPN"

!define MUI_ICON "zainvpn.ico"
!define MUI_UNICON "zainvpn.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TEXT "This installs zainVPN, a virtual LAN for playing games with friends.$\r$\n$\r$\nAfter installing, open zainVPN and paste the invite code a friend sent you (or create your own network).$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_TITLE "zainVPN is ready"
!define MUI_FINISHPAGE_TEXT "zainVPN is installed and running, and starts automatically with Windows.$\r$\n$\r$\nOpen it, then create a network or paste an invite code from a friend."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open zainVPN"
!define MUI_FINISHPAGE_RUN_FUNCTION OpenApp

!insertmacro MUI_PAGE_WELCOME
Page custom SettingsPage SettingsLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Var Nick
Var Server
Var Invite
Var NickField
Var ServerField

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "zainVPN needs 64-bit Windows 10 or later."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all

  StrCpy $Server "${SERVER}"
  ReadEnvStr $Nick "COMPUTERNAME"
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/SERVER=" $1
  ${IfNot} ${Errors}
    StrCpy $Server $1
  ${EndIf}
  ClearErrors
  ${GetOptions} $0 "/NAME=" $1
  ${IfNot} ${Errors}
    StrCpy $Nick $1
  ${EndIf}
  ClearErrors
  ${GetOptions} $0 "/INVITE=" $1
  ${IfNot} ${Errors}
    StrCpy $Invite $1
  ${EndIf}
FunctionEnd

; The settings page is skipped on upgrades: the existing config.json is kept.
Function SettingsPage
  ${If} ${FileExists} "${CONFIG}"
    Abort
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "Set up zainVPN" "Choose the name your friends will see."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 12u "Nickname"
  Pop $0
  ${NSD_CreateText} 0 13u 100% 13u "$Nick"
  Pop $NickField
  ${NSD_CreateLabel} 0 34u 100% 12u "Coordinator address"
  Pop $0
  ${NSD_CreateText} 0 47u 100% 13u "$Server"
  Pop $ServerField
  ${NSD_CreateLabel} 0 64u 100% 24u "Already filled in if you downloaded zainVPN from your group's page. You join a network with an invite code after installing."
  Pop $0
  nsDialogs::Show
FunctionEnd

Function SettingsLeave
  ${NSD_GetText} $NickField $Nick
  ${NSD_GetText} $ServerField $Server
  ${If} $Nick == ""
  ${OrIf} $Server == ""
    MessageBox MB_ICONEXCLAMATION "Please fill in both fields."
    Abort
  ${EndIf}
FunctionEnd

; Arg makes a value safe inside a double-quoted command-line argument.
!macro Arg out in
  ${WordReplace} "${in}" '"' "" "+" ${out}
  StrCpy $R9 ${out} 1 -1
  ${DoWhile} $R9 == "\"
    StrCpy ${out} ${out} -1
    StrCpy $R9 ${out} 1 -1
  ${Loop}
!macroend

Function StopRunning
  nsExec::Exec '"$SYSDIR\taskkill.exe" /IM zainvpn-app.exe /F'
  Pop $0
  ${If} ${FileExists} "$INSTDIR\zainvpn.exe"
    DetailPrint "Stopping the zainVPN service..."
    nsExec::ExecToLog '"$INSTDIR\zainvpn.exe" stop'
    Pop $0
  ${EndIf}
FunctionEnd

Section "zainVPN" SecMain
  SetOutPath "$INSTDIR"
  Call StopRunning

  File "${SRC}\zainvpn.exe"
  File "${SRC}\zainvpn-app.exe"
  File "${SRC}\wintun.dll"
  File "/oname=wintun-LICENSE.txt" "..\third_party\wintun\LICENSE.txt"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Leftovers from the earlier Inno Setup installer.
  Delete "$SMPROGRAMS\zainVPN.url"
  Delete "$DESKTOP\zainVPN.url"
  CreateShortCut "$SMPROGRAMS\zainVPN.lnk" "$INSTDIR\zainvpn-app.exe" "" "$INSTDIR\zainvpn-app.exe" 0
  CreateShortCut "$DESKTOP\zainVPN.lnk" "$INSTDIR\zainvpn-app.exe" "" "$INSTDIR\zainvpn-app.exe" 0

  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${APP}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\zainvpn-app.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" $0

  ; "install" merges these into config.json (keeping anything already there),
  ; sets up the firewall rule and the Windows service, and starts it.
  StrCpy $0 ""
  ${If} $Server != ""
    !insertmacro Arg $1 $Server
    StrCpy $0 '$0 --server "$1"'
  ${EndIf}
  ${If} $Nick != ""
  ${AndIfNot} ${FileExists} "${CONFIG}"
    !insertmacro Arg $1 $Nick
    StrCpy $0 '$0 --name "$1"'
  ${EndIf}
  ${If} $Invite != ""
    !insertmacro Arg $1 $Invite
    StrCpy $0 '$0 --invite "$1"'
  ${EndIf}
  DetailPrint "Starting the zainVPN service..."
  nsExec::ExecToLog '"$INSTDIR\zainvpn.exe" install$0'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "zainVPN couldn't start its background service (code $0).$\r$\nSee $COMMONPROGRAMDATA\zainVPN\zainvpn.log, or run zainvpn.exe install as administrator for details." /SD IDOK
  ${EndIf}
SectionEnd

; Launch through Explorer so the app runs as the signed-in user, not elevated.
Function OpenApp
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\zainvpn-app.exe"'
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "Uninstall"
  nsExec::Exec '"$SYSDIR\taskkill.exe" /IM zainvpn-app.exe /F'
  Pop $0
  DetailPrint "Removing the zainVPN service, adapter and settings..."
  nsExec::ExecToLog '"$INSTDIR\zainvpn.exe" uninstall'
  Pop $0
  Delete "$SMPROGRAMS\zainVPN.lnk"
  Delete "$DESKTOP\zainVPN.lnk"
  Delete "$INSTDIR\zainvpn.exe"
  Delete "$INSTDIR\zainvpn-app.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\wintun-LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
