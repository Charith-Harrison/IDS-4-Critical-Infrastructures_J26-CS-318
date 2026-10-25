[CmdletBinding()]
param(
    [string]$Python,
    [string]$DockerStoragePath
)
$ErrorActionPreference = 'Stop'
if (-not $Python) {
    $c3PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $c3PythonCommand) { throw 'Install Python 3.11+ or supply -Python with the actual executable path.' }
    $Python = $c3PythonCommand.Source
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Install and start Docker Desktop with Linux containers first. Read START_HERE.md.'
}
& $Python -B (Join-Path $PSScriptRoot 'verify_bundle.py')
if ($LASTEXITCODE -ne 0) { throw 'Portable bundle/Python verification failed. Nothing has been collected.' }
$c3Manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BUNDLE_MANIFEST.json') -Raw | ConvertFrom-Json
$c3DockerPlatform = & docker info --format '{{.OSType}}/{{.Architecture}}'
if ($LASTEXITCODE -ne 0) { throw 'Docker is unavailable. Start Docker Desktop and retry setup.' }
if ($c3DockerPlatform -notmatch '^linux/(x86_64|amd64)$') {
    throw ('This delivery requires Linux containers on x86_64/amd64; found ' + $c3DockerPlatform)
}
$c3ImageId = $c3Manifest.image_id
$c3ImageStore = & docker info --format '{{json .DriverStatus}}'
if ($LASTEXITCODE -ne 0 -or $c3ImageStore -notmatch 'io\.containerd\.snapshotter\.v1') {
    throw 'The frozen archive uses an OCI image-index identity. Enable the containerd image store as described in START_HERE.md; classic image storage is unsupported.'
}
$c3KnownImages = @(& docker image ls --no-trunc --quiet)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect local Docker images.' }
if ($c3KnownImages -notcontains $c3ImageId) {
    & docker image load --input (Join-Path $PSScriptRoot 'component3_main_collection/v1_20261025/evidence/manual-runtime.tar')
    if ($LASTEXITCODE -ne 0) { throw 'Loading the saved local runtime failed. Do not build/pull a replacement.' }
}
$c3LoadedIdentity = & docker image inspect --format '{{.Id}}|{{.Os}}|{{.Architecture}}' $c3ImageId
if ($LASTEXITCODE -ne 0 -or $c3LoadedIdentity -ne ($c3ImageId + '|linux|amd64')) {
    throw 'Loaded image identity/platform mismatch. Use the documented containerd image store; do not change the frozen image receipt.'
}
$c3LauncherPath = Join-Path $PSScriptRoot 'component3_main_collection/v1_20261025/collect-main.ps1'
# Use a child PowerShell: the frozen script deliberately calls exit.
$c3ShellPath = (Get-Process -Id $PID).Path
$c3ChildArgs = @('-NoProfile', '-File', $c3LauncherPath, '-Preflight', '-Python', $Python)
if ($DockerStoragePath) { $c3ChildArgs += @('-DockerStoragePath', $DockerStoragePath) }
& $c3ShellPath @c3ChildArgs
if ($LASTEXITCODE -ne 0) { throw 'Frozen preflight failed. Read the exact error; no collection started.' }
Write-Host ''
Write-Host 'SETUP COMPLETE. No Modbus traffic generated; main collection has NOT started.'
Write-Host 'Read START_HERE.md, then manually run collect-main.ps1 -Start with the same Python/path settings.'
