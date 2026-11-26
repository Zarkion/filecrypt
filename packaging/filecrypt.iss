; Inno Setup script for the per-user Windows installer.
;
; Wraps the portable PyInstaller build (dist\filecrypt, made by filecrypt.spec)
; in a setup .exe that installs for the current user only: no administrator
; rights, files go to %LOCALAPPDATA%\Programs\filecrypt, and Explorer entries
; go under HKEY_CURRENT_USER (filecrypt-gui --register). Uninstalling runs
; filecrypt-gui --unregister before the files are removed.
;
; THE INSTALLER IS UNSIGNED. Windows SmartScreen will warn about it until a
; code-signing certificate is set up. Check the .sha256 published next to it.
;
; Build (from the repository root, after PyInstaller):
;   iscc /DAppVersion=0.1.0 packaging\filecrypt.iss
; The setup .exe lands in dist-installer\.

#ifndef AppVersion
  #error Pass the version: iscc /DAppVersion=X.Y.Z packaging\filecrypt.iss
#endif
#ifndef OutputName
  #define OutputName "filecrypt-" + AppVersion + "-windows-x64-unsigned-setup"
#endif

[Setup]
; Never change AppId: upgrades and uninstall find the old install through it.
AppId={{7B0E3C52-6F7A-4C1D-9E0B-2B8F4F1C9A61}
AppName=filecrypt
AppVersion={#AppVersion}
AppVerName=filecrypt {#AppVersion}
AppPublisher=filecrypt
AppPublisherURL=https://github.com/Zarkion/filecrypt
AppSupportURL=https://github.com/Zarkion/filecrypt/issues
PrivilegesRequired=lowest
DefaultDirName={autopf}\filecrypt
DefaultGroupName=filecrypt
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SourceDir=..
OutputDir=dist-installer
OutputBaseFilename={#OutputName}
UninstallDisplayIcon={app}\filecrypt-gui.exe
UninstallDisplayName=filecrypt
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Files]
Source: "dist\filecrypt\*"; DestDir: "{app}"; Excludes: "filecrypt-selftest.exe"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\filecrypt"; Filename: "{app}\filecrypt-gui.exe"

[InstallDelete]
; An upgrade replaces the whole bundle, so no stale DLL from an older version stays.
Type: filesandordirs; Name: "{app}\_internal"

[Code]
function RunGui(const Arg: String): Integer;
var
  Code: Integer;
begin
  if Exec(ExpandConstant('{app}\filecrypt-gui.exe'), Arg + ' --quiet', '',
          SW_HIDE, ewWaitUntilTerminated, Code) then
    Result := Code
  else
    Result := -1;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if RunGui('--register') <> 0 then
      SuppressibleMsgBox('filecrypt was installed, but adding it to Explorer''s ' +
        'right-click menu failed. Run "filecrypt-gui --register" to try again.',
        mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  { Before the files go, while filecrypt-gui.exe still exists. A failure must
    not stop the uninstall, so the result is ignored. }
  if CurUninstallStep = usUninstall then
    RunGui('--unregister');
end;
