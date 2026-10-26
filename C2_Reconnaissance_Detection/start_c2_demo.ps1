# Start the Component 2 demo (offline after setup). Usage, from this folder:
#   powershell -ExecutionPolicy Bypass -File .\start_c2_demo.ps1
# Options: -Port 8020   -NoBrowser
param([int]$Port = 8020, [switch]$NoBrowser)
$ErrorActionPreference = 'Stop'

$C2 = $PSScriptRoot
$Demo = Join-Path $C2 'demo'
$Py = Join-Path $Demo '.venv\Scripts\python.exe'

if (-not (Test-Path (Join-Path $Demo '.venv\c2_setup_ok.txt'))) {
    Write-Host 'First run: running setup_c2_demo.ps1 ...' -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File (Join-Path $C2 'setup_c2_demo.ps1')
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

$url = "http://127.0.0.1:$Port/"
Write-Host ''
Write-Host '  Component 2 demo running' -ForegroundColor Green
Write-Host "  Open: $url" -ForegroundColor Green
Write-Host '  Stop: press Ctrl+C in this window' -ForegroundColor Green
Write-Host ''
if (-not $NoBrowser) { Start-Job -ScriptBlock { param($u) Start-Sleep 3; Start-Process $u } -ArgumentList $url | Out-Null }
& $Py -m uvicorn server:app --app-dir $Demo --host 127.0.0.1 --port $Port --log-level warning
if ($LASTEXITCODE -ne 0) { Write-Host "  Demo server stopped (exit code $LASTEXITCODE)." -ForegroundColor Yellow }
