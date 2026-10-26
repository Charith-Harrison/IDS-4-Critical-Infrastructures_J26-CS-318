# Start the Component 2 viva demo (offline). Usage, from this folder:
#   powershell -ExecutionPolicy Bypass -File .\start_c2_demo.ps1
# Options: -Port 8020   -NoBrowser
param([int]$Port = 8020, [switch]$NoBrowser)
$ErrorActionPreference = 'Stop'

$C2 = $PSScriptRoot
$Repo = Split-Path $C2 -Parent
$Demo = Join-Path $C2 'demo'
$Bundle = Join-Path $C2 'demo_bundle'
$Dist = Join-Path $C2 'frontend\dist\index.html'
$Venv = Join-Path $Demo '.venv'
$Py = Join-Path $Venv 'Scripts\python.exe'

function Fail($msg) { Write-Host "`n  $msg`n" -ForegroundColor Red; exit 1 }

if ($C2.Length -gt 150) {
    Fail "Folder path is too long for Windows ($($C2.Length) characters; Python DLLs exceed the 260-character limit). Move the folder to a short path such as C:\C2demo."
}
if (-not (Test-Path (Join-Path $Bundle 'bundle_manifest.json'))) {
    Fail "Demo bundle missing: extract the viva package so that $Bundle exists."
}
if (-not (Test-Path (Join-Path $Repo 'component2_testbed\c2tb\model_data.py'))) {
    Fail "component2_testbed\c2tb not found next to C2_Reconnaissance_Detection (git pull branch-ghost)."
}

# One-time setup: Python 3.10-3.13 virtual environment with the pinned demo dependencies (needs internet once).
if (-not (Test-Path $Py)) {
    $base = $null
    foreach ($v in '3.13', '3.12', '3.11', '3.10') {
        try { & py "-$v" -c "import sys" 2>$null; if ($LASTEXITCODE -eq 0) { $base = @('py', "-$v"); break } } catch {}
    }
    if (-not $base) {
        try {
            $ok = & python -c "import sys; print(int((3,10) <= sys.version_info[:2] <= (3,13)))" 2>$null
            if ($ok -eq '1') { $base = @('python') }
        } catch {}
    }
    if (-not $base) { Fail 'Python 3.10-3.13 is required (python.org). Python 3.14 is not supported by scikit-learn 1.5.2.' }
    Write-Host 'One-time setup: creating Python environment...' -ForegroundColor Cyan
    if ($base.Count -eq 2) { & $base[0] $base[1] -m venv $Venv } else { & $base[0] -m venv $Venv }
    & $Py -m pip install --disable-pip-version-check -q -r (Join-Path $Demo 'requirements-demo.txt')
    if ($LASTEXITCODE -ne 0) { Remove-Item -Recurse -Force $Venv; Fail 'Dependency install failed (internet needed for the one-time setup).' }
}

# Frontend: the viva package ships a built frontend; rebuild only if it is missing and Node.js is available.
if (-not (Test-Path $Dist)) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Host 'Building frontend...' -ForegroundColor Cyan
        Push-Location (Join-Path $C2 'frontend')
        npm install --no-audit --no-fund; if ($LASTEXITCODE -eq 0) { npm run build }
        Pop-Location
    }
    if (-not (Test-Path $Dist)) { Fail 'frontend\dist missing: extract it from the viva package (or install Node.js).' }
}

$url = "http://127.0.0.1:$Port/"
Write-Host ''
Write-Host '  Component 2 demo starting' -ForegroundColor Green
Write-Host "  Open: $url" -ForegroundColor Green
Write-Host '  Stop: press Ctrl+C in this window' -ForegroundColor Green
Write-Host ''
if (-not $NoBrowser) { Start-Job -ScriptBlock { param($u) Start-Sleep 3; Start-Process $u } -ArgumentList $url | Out-Null }
& $Py -m uvicorn server:app --app-dir $Demo --host 127.0.0.1 --port $Port --log-level warning
if ($LASTEXITCODE -ne 0) { Fail "Demo server stopped with an error (exit code $LASTEXITCODE). See the messages above." }
