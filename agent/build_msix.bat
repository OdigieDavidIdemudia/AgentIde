@echo off
REM AgentIDE MSIX Packaging Script
REM Requires: Windows 10 SDK (MakeAppx.exe, SignTool.exe)

setlocal enabledelayedexpansion

set APP_NAME=AgentIDE
set VERSION=0.4.0.0
set PUBLISHER=CN=AgentIDE Project
set OUTPUT_DIR=msix_output
set TEMP_DIR=%OUTPUT_DIR%\package_temp

echo Building MSIX package for %APP_NAME% v%VERSION%...

REM Clean previous builds
if exist "%OUTPUT_DIR%" rmdir /s /q "%OUTPUT_DIR%"
if exist "%TEMP_DIR%" rmdir /s /q "%TEMP_DIR%"

mkdir "%TEMP_DIR%\Assets"
mkdir "%TEMP_DIR%\VFS\ProgramFiles\AgentIDE"

REM Copy application files
copy agentide.exe "%TEMP_DIR%\VFS\ProgramFiles\AgentIDE\"
copy README.md "%TEMP_DIR%\VFS\ProgramFiles\AgentIDE\"
copy Package.appxmanifest "%TEMP_DIR%\AppxManifest.xml"

REM Generate placeholder assets (replace with real icons)
echo Generating placeholder assets...
powershell -Command "
  Add-Type -AssemblyName System.Drawing
  $bmp = New-Object System.Drawing.Bitmap(150,150)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.Clear([System.Drawing.Color]::FromArgb(0,102,204))
  $font = New-Object System.Drawing.Font('Segoe UI', 48, [System.Drawing.FontStyle]::Bold)
  $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
  $g.DrawString('AI', $font, $brush, 25, 30)
  $bmp.Save('msix_output\package_temp\Assets\Square150x150Logo.png')
  $bmp44 = New-Object System.Drawing.Bitmap(44,44)
  $g44 = [System.Drawing.Graphics]::FromImage($bmp44)
  $g44.Clear([System.Drawing.Color]::FromArgb(0,102,204))
  $g44.DrawString('AI', (New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)), $brush, 5, 8)
  $bmp44.Save('msix_output\package_temp\Assets\Square44x44Logo.png')
  $bmpStore = New-Object System.Drawing.Bitmap(50,50)
  $gStore = [System.Drawing.Graphics]::FromImage($bmpStore)
  $gStore.Clear([System.Drawing.Color]::FromArgb(0,102,204))
  $gStore.DrawString('AI', (New-Object System.Drawing.Font('Segoe UI', 20, [System.Drawing.FontStyle]::Bold)), $brush, 10, 10)
  $bmpStore.Save('msix_output\package_temp\Assets\StoreLogo.png')
"

echo Creating MSIX package...
MakeAppx.exe pack /d "%TEMP_DIR%" /p "%OUTPUT_DIR%\%APP_NAME%_%VERSION%.msix" /l /nv /o

if %ERRORLEVEL% neq 0 (
    echo ERROR: MakeAppx failed
    exit /b 1
)

echo.
echo Package created: %OUTPUT_DIR%\%APP_NAME%_%VERSION%.msix
echo.
echo To install (requires sideloading enabled):
echo   Add-AppxPackage -Path "%OUTPUT_DIR%\%APP_NAME%_%VERSION%.msix"
echo.
echo To sign (for distribution):
echo   SignTool.exe sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 "%OUTPUT_DIR%\%APP_NAME%_%VERSION%.msix"

pause