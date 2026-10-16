@echo off
REM AgentIDE Professional Build Script
REM Builds: deterministic binary, professional installer, MSIX package

setlocal enabledelayedexpansion

REM Single source of truth for the release version. version.json is kept in
REM sync below, and build_msi.bat / installer_pro.iss read it so the agent
REM binary, MSI and Inno installer can never drift apart (that drift is what
REM let a v0.1.0 installer coexist with a v0.4.0 agent).
REM The file is {"version": "0.4.3"} so take the token after the colon and
REM strip quotes, spaces and the trailing brace.
set VERSION=
for /f "usebackq delims=" %%v in ("version.json") do (
    for /f "tokens=2 delims=:" %%w in ("%%v") do set "VERSION=%%~w"
)
set "VERSION=%VERSION: =%"
set "VERSION=%VERSION:"=%"
set "VERSION=%VERSION:}=%"
if "%VERSION%"=="" (
    echo ERROR: could not read version from version.json
    exit /b 1
)

echo ==========================================
echo AgentIDE Professional Build v%VERSION%
echo ==========================================
echo.

REM 0. Keep the self-update manifest in sync with this build so the dashboard
REM    advertises the correct version/SHA-256 to already-installed agents.
echo {"version":"%VERSION%"} > version.json
echo [0/4] Wrote version.json (v%VERSION%)
echo.

REM 1. Build deterministic Go binary.
REM NOTE 1: the old "-buildid=" flag was passed via -ldflags, where it collides
REM with the Go linker's own -buildid option and fails the build.
REM NOTE 2: %DATE% expands to "Sat 10/10/2026" - spaces and slashes break the
REM -ldflags quoting, so use a sortable ISO-ish stamp instead.
echo [1/5] Building deterministic agentide.exe...
for /f "tokens=2-4 delims=/ " %%d in ("%DATE%") do set BUILDDATE=%%d-%%f-%%g
go build -trimpath -ldflags="-s -w -X main.version=%VERSION% -X main.buildDate=%BUILDDATE%" -o agentide.exe .
if %ERRORLEVEL% neq 0 (
    echo ERROR: Go build failed
    exit /b 1
)
echo Binary: agentide.exe
for %%f in (agentide.exe) do echo Size: %%~zf bytes
CertUtil -hashfile agentide.exe SHA256
echo.

REM 1b. Build system tray companion app
echo [1b/5] Building system tray companion (agentide-tray.exe)...
REM NOTE: the tray module lives at the repo root, NOT under agent\. This used to
REM be "cd tray" from agent\, which silently failed (cmd's cd does not abort on a
REM missing directory), leaving the cwd at agent\ and building the AGENT module
REM into ..\agentide-tray.exe. The installer then packaged a second copy of
REM agentide.exe as the tray, so a "tray" that was actually a duplicate agent
REM service shipped to the VM. The existence checks below turn that into a hard
REM failure rather than a wrong binary.
if not exist "..\tray\go.mod" (
    echo ERROR: tray module not found at ..\tray - expected %CD%\..\tray\go.mod
    exit /b 1
)
REM -H windowsgui keeps a console window from flashing when the tray is started
REM by hand. The installer passes runhidden, but a manual launch should behave
REM the same way.
pushd ..\tray
go build -trimpath -ldflags="-s -w -H windowsgui -X main.version=%VERSION% -X main.buildDate=%BUILDDATE%" -o ..\agent\agentide-tray.exe .
if %ERRORLEVEL% neq 0 (
    popd
    echo ERROR: Tray build failed
    exit /b 1
)
popd
REM Confirm the artefact is really the tray. A copy of agentide.exe here would
REM mean the build silently regressed to the bug above, and it is cheap to
REM check: the tray links systray, the agent does not.
findstr /m /c:"getlantern/systray" agentide-tray.exe >nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: agentide-tray.exe does not contain the systray symbol - the tray build is wrong
    exit /b 1
)
echo Binary: agentide-tray.exe
for %%f in (agentide-tray.exe) do echo Size: %%~zf bytes
CertUtil -hashfile agentide-tray.exe SHA256
echo.

REM 2. Build professional installer.
REM Locate the Inno Setup compiler across versions/install locations rather than
REM hardcoding one path — Inno Setup 7 installs per-user while 6 was typically
REM in Program Files (x86).
set ISCC=
for %%P in (
    "%LOCALAPPDATA%\Programs\Inno Setup 7\ISCC.exe"
    "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    "C:\Program Files\Inno Setup 6\ISCC.exe"
    "C:\Program Files (x86)\Inno Setup 7\ISCC.exe"
    "C:\Program Files\Inno Setup 7\ISCC.exe"
) do (
    if not defined ISCC if exist %%P set ISCC=%%~P
)

if defined ISCC (
    echo [2/4] Building professional installer...
    echo   using %ISCC%
    "%ISCC%" installer_pro.iss /DAppVersion=%VERSION%
    REM !ERRORLEVEL! not %ERRORLEVEL%: inside a parenthesised block the latter is
    REM expanded when the block is parsed, i.e. before ISCC has run, so a failed
    REM compile was silently swallowed and the build still printed COMPLETE.
    if !ERRORLEVEL! neq 0 (
        echo ERROR: Inno Setup compilation failed
        exit /b 1
    )
    echo Installer: AgentIDE_Installer_v%VERSION%.exe
    echo.
) else (
    echo WARNING: Inno Setup compiler ^(ISCC.exe^) not found - skipping the EXE installer.
    echo          Install it from https://jrsoftware.org/isdl.php
    echo.
)

REM 2b. Build the MSI too. Previously the MSI was only produced by a separate
REM manual build_msi.bat run, which is how it drifted to a different version
REM than the Inno installer — and how an old agent ended up deployed from a
REM stale installer. One command now produces consistent artifacts.
echo [2b/4] Building MSI package...
where dotnet >nul 2>&1
if %ERRORLEVEL% equ 0 (
    call build_msi.bat
    REM !ERRORLEVEL! not %ERRORLEVEL%: this sits inside the block opened on the
    REM line above, so %ERRORLEVEL% would be the value from before build_msi.bat
    REM ran. A failed MSI build is fatal rather than a warning, because leaving
    REM a stale MSI in msi_output is precisely the version drift this step was
    REM added to prevent.
    if !ERRORLEVEL! neq 0 (
        echo ERROR: MSI build failed - aborting rather than leaving a stale MSI in msi_output
        exit /b 1
    )
) else (
    echo WARNING: dotnet SDK not found - skipping MSI.
    echo          Install the .NET SDK to build the MSI: https://dotnet.microsoft.com
)
echo.

REM 3. Build MSIX package (optional - requires Windows SDK)
echo [3/4] Building MSIX package...
if exist "%WindowsSdkDir%\bin\10.0.22621.0\x64\MakeAppx.exe" (
    call build_msix.bat
) else (
    echo WARNING: Windows SDK not found, skipping MSIX build
    echo Install Windows 10 SDK from Visual Studio Installer
)
echo.

REM 4. Verify signatures (if cert available)
echo [4/4] Verifying...
if exist "signtool.exe" (
    signtool.exe verify /pa agentide.exe
    signtool.exe verify /pa AgentIDE_Installer_v%VERSION%.exe
) else (
    echo WARNING: SignTool not found, skipping signature verification
)

echo.
echo ==========================================
echo BUILD COMPLETE
echo ==========================================
echo.
echo Output files:
echo   - agentide.exe (deterministic build)
echo   - AgentIDE_Installer_v%VERSION%.exe (professional installer)
echo   - msix_output\AgentIDE_%VERSION%.0.msix (MSIX package, if SDK available)
echo.
echo Next steps:
echo   1. Test installer on clean VM
echo   2. Submit to Microsoft: python submit_to_microsoft.py --installer AgentIDE_Installer_v%VERSION%.exe --agent agentide.exe --email your@email.com
echo   3. Get code signing cert for production distribution

pause
