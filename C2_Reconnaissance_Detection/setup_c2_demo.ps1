# One-time setup of the Component 2 demo (needs internet once, for pip). Usage, from this folder:
#   powershell -ExecutionPolicy Bypass -File .\setup_c2_demo.ps1
# Steps: check location -> check Git checkout -> verify handoff package -> Python environment -> frontend -> self-test.
$ErrorActionPreference = 'Stop'

$C2 = $PSScriptRoot
$Repo = Split-Path $C2 -Parent
$Demo = Join-Path $C2 'demo'
$Venv = Join-Path $Demo '.venv'
$Py = Join-Path $Venv 'Scripts\python.exe'
$Req = Join-Path $Demo 'requirements-demo.txt'
$Marker = Join-Path $Venv 'c2_setup_ok.txt'

function Step($msg) { Write-Host "`n== $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "`n  SETUP FAILED: $msg`n" -ForegroundColor Red; exit 1 }

Step 'Location'
if ($C2.Length -gt 150) {
    Fail "Folder path is $($C2.Length) characters; Windows' 260-character limit breaks Python DLL loading. Move the repository to a short path such as C:\C2."
}
Write-Host "  $Repo"

Step 'Git checkout'
foreach ($f in 'component2_testbed\c2tb\model_data.py', 'C2_Reconnaissance_Detection\demo\server.py', 'component2_testbed\FINAL_RESULTS.md') {
    if (-not (Test-Path (Join-Path $Repo $f))) { Fail "$f missing: clone/pull branch-ghost first." }
}
Write-Host '  tracked source present'

Step 'Python'
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
function Base { if ($base.Count -eq 2) { & $base[0] $base[1] @args } else { & $base[0] @args } }
Write-Host "  using: $($base -join ' ')"

Step 'Handoff package'
Base (Join-Path $Demo 'verify_handoff.py')
if ($LASTEXITCODE -ne 0) { Fail 'extract C2_handoff_package.zip into the repository root (it creates HANDOFF_MANIFEST.json there).' }

Step 'Python environment'
$reqHash = (Get-FileHash $Req -Algorithm SHA256).Hash
if ((Test-Path $Marker) -and ((Get-Content $Marker -Raw).Trim() -eq $reqHash)) {
    Write-Host '  already installed'
} else {
    if (Test-Path $Venv) { Remove-Item -Recurse -Force $Venv }
    Base -m venv $Venv
    & $Py -m pip install --disable-pip-version-check -q -r $Req
    if ($LASTEXITCODE -ne 0) { Remove-Item -Recurse -Force $Venv; Fail 'pip install failed (internet needed once).' }
    Set-Content -Path $Marker -Value $reqHash -Encoding ascii
    Write-Host '  installed pinned packages'
}

Step 'Frontend'
$Dist = Join-Path $C2 'frontend\dist\index.html'
if (-not (Test-Path $Dist)) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Push-Location (Join-Path $C2 'frontend'); npm install --no-audit --no-fund; if ($LASTEXITCODE -eq 0) { npm run build }; Pop-Location
    }
    if (-not (Test-Path $Dist)) { Fail 'frontend\dist missing: it is in the handoff package.' }
}
Write-Host '  built frontend present'

Step 'Self-test (frozen models vs saved held-out predictions)'
Push-Location $Demo
& $Py -W ignore selftest.py
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { Fail 'self-test failed (see above).' }

Write-Host "`n  Setup complete. Start with:  powershell -ExecutionPolicy Bypass -File .\start_c2_demo.ps1`n" -ForegroundColor Green
