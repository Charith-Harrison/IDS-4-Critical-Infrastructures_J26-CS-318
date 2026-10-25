[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$SkipBuild,
    [int]$Seed = 4010,
    [ValidateRange(1, 5)][int]$Groups = 2
)
$ErrorActionPreference = 'Stop'
$labDirectory = $PSScriptRoot
$composePath = Join-Path $labDirectory 'compose.yaml'
$outputDirectory = Join-Path $labDirectory 'outputs'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is not installed or this terminal has not refreshed its PATH. Install Docker Desktop from https://docs.docker.com/desktop/setup/install/windows-install/ then reopen PowerShell.'
}
$serverType = & docker info --format '{{.OSType}}' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Open Docker Desktop and wait for Engine running, then retry. Docker reported: $serverType"
}
if (($serverType | Out-String).Trim() -ne 'linux') { throw 'Select Linux containers in Docker Desktop for this lab.' }
& docker compose version
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose is unavailable; update/install Docker Desktop.' }
& docker compose -f $composePath config --quiet
if ($LASTEXITCODE -ne 0) { throw 'The supplied compose.yaml did not validate.' }
Write-Host 'Docker Linux engine and Compose are available. Runtime network is NONE; only container loopback is used.'
if ($CheckOnly) {
    Write-Host 'CHECK ONLY: no image build, capture or dataset collection performed.'
    return
}
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
if (-not $SkipBuild) {
    Write-Host 'Building the small lab image. This initial build downloads Python/tcpdump.'
    & docker compose -f $composePath build lab
    if ($LASTEXITCODE -ne 0) { throw 'Image build failed. No pilot was started. Read the build error above.' }
}
$imageIdentityText = & docker image inspect kaveesha-c3-pilot:0.1.0
if ($LASTEXITCODE -ne 0) { throw 'Lab image missing. Run again without -SkipBuild.' }
$imageIdentity = $imageIdentityText | ConvertFrom-Json
Write-Host 'Running offline tests inside the container.'
& docker compose -f $composePath run --rm --no-deps lab python -B -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Offline tests failed; no captured pilot was started.' }
$beforeNames = @(Get-ChildItem -LiteralPath $outputDirectory -Directory | ForEach-Object Name)
$started = [DateTime]::UtcNow.ToString('o')
$pilotExitCode = $null
try {
    Write-Host 'Running one bounded feasibility pilot with real TCP and packet capture.'
    & docker compose -f $composePath run --rm --no-deps lab python -B -m c3lab run --output /output --seed $Seed --groups $Groups
    $pilotExitCode = $LASTEXITCODE
}
finally {
    $newRuns = @(Get-ChildItem -LiteralPath $outputDirectory -Directory | Where-Object { $_.Name -notin $beforeNames })
    if ($newRuns.Count -eq 1) {
        $metadata = [ordered]@{
            purpose = 'FEASIBILITY_PILOT_NOT_TRAINING_DATASET'
            started_at_utc = $started
            ended_at_utc = [DateTime]::UtcNow.ToString('o')
            seed = $Seed
            groups = $Groups
            docker_exit_code = $pilotExitCode
            docker_image = $imageIdentity
            compose_sha256 = (Get-FileHash -LiteralPath $composePath -Algorithm SHA256).Hash.ToLowerInvariant()
            image_rebuild_note = 'Image ID is recorded. Base-image tag and apt repositories can move; retain this identity and source hashes.'
        }
        $metadata | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $newRuns[0].FullName 'host_execution.json') -Encoding UTF8
        Write-Host "Run folder: $($newRuns[0].FullName)"
    }
}
if ($pilotExitCode -ne 0) { throw 'Pilot or capture verification failed. Keep its run folder; inspect run_manifest.json, capture.log and validation_report.json. Do not treat its labels as verified.' }
Write-Host 'Pilot command succeeded. Read validation_report.json and explain the examples before collecting anything larger.'
