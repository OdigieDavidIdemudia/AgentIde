@echo off
REM AgentIde MSI Packaging Script (WiX Toolset v6 via dotnet build)
REM Requires: a .NET SDK (https://dotnet.microsoft.com) - the WiX build tools
REM            restore automatically from NuGet on first build.
REM Run from the agent\ directory (needs agentide.exe built first).

setlocal

set APP_NAME=AgentIDE
set VERSION=0.4.0
set OUTPUT_DIR=msi_output

echo Building MSI package for %APP_NAME% v%VERSION%...

where dotnet >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: dotnet SDK not found. Install from https://dotnet.microsoft.com
    exit /b 1
)

if not exist agentide.exe (
    echo ERROR: agentide.exe not found - run build_pro.bat or: go build -o agentide.exe .
    exit /b 1
)

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Compiling package (dotnet build^)...
dotnet build AgentIde.wixproj -c Release -o %OUTPUT_DIR%
if %ERRORLEVEL% neq 0 (
    echo ERROR: dotnet build failed
    exit /b 1
)

set MSI_PATH=%OUTPUT_DIR%\%APP_NAME%_%VERSION%.msi
if not exist "%MSI_PATH%" (
    echo ERROR: expected package not found at %MSI_PATH% - contents:
    dir /b "%OUTPUT_DIR%"
    exit /b 1
)

echo.
echo Package created: %MSI_PATH%
CertUtil -hashfile "%MSI_PATH%" SHA256
echo.
echo To install silently:
echo   msiexec /i "%MSI_PATH%" /qn DASHBOARD=wss://host:8080 TOKEN^=<AGENT_TOKEN^>
echo.
echo To install silently with no dashboard (local only^):
echo   msiexec /i "%MSI_PATH%" /qn
echo.
echo To uninstall:
echo   msiexec /x "%MSI_PATH%" /qn
echo.
echo To sign (for distribution^):
echo   SignTool.exe sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 "%MSI_PATH%"
echo.

pause
