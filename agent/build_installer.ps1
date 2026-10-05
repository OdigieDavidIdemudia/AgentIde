$isccPath = "$env:LOCALAPPDATA\Programs\Inno Setup 7\iscc.exe"
if (-Not (Test-Path $isccPath)) {
    $isccPath = "C:\Program Files\Inno Setup 7\iscc.exe"
}
if (-Not (Test-Path $isccPath)) {
    $isccPath = "C:\Program Files (x86)\Inno Setup 7\iscc.exe"
}

if (-Not (Test-Path $isccPath)) {
    Write-Host "Inno Setup compiler not found. Please install Inno Setup 7." -ForegroundColor Red
    exit 1
}

Write-Host "Compiling AgentIDE Installer..." -ForegroundColor Cyan
& $isccPath "installer.iss"

if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully compiled installer to AgentIDE_Installer.exe!" -ForegroundColor Green
} else {
    Write-Host "Failed to compile installer." -ForegroundColor Red
}
