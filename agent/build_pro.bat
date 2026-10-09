@echo off
REM AgentIDE Professional Build Script
REM Builds: deterministic binary, professional installer, MSIX package

setlocal enabledelayedexpansion

set VERSION=0.4.0

echo ==========================================
echo AgentIDE Professional Build v%VERSION%
echo ==========================================
echo.

REM 0. Keep the self-update manifest in sync with this build so the dashboard
REM    advertises the correct version/SHA-256 to already-installed agents.
echo {"version":"%VERSION%"} > version.json
echo [0/4] Wrote version.json (v%VERSION%)
echo.

REM 1. Build deterministic Go binary
echo [1/4] Building deterministic agentide.exe...
go build -trimpath -ldflags="-s -w -buildid= -X main.version=%VERSION% -X main.buildDate=%DATE%" -o agentide.exe .
if %ERRORLEVEL% neq 0 (
    echo ERROR: Go build failed
    exit /b 1
)
echo Binary: agentide.exe
for %%f in (agentide.exe) do echo Size: %%~zf bytes
CertUtil -hashfile agentide.exe SHA256
echo.

REM 2. Build professional installer
echo [2/4] Building professional installer...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer_pro.iss
if %ERRORLEVEL% neq 0 (
    echo ERROR: Inno Setup compilation failed
    exit /b 1
)
echo Installer: AgentIDE_Installer_v%VERSION%.exe
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
