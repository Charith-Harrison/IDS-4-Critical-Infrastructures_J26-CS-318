[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Run)
$ErrorActionPreference = 'Stop'
if ($Run -notmatch '^pilot-[A-Za-z0-9-]+$') { throw 'Use only the pilot run folder name, for example pilot-20261024T120000Z-a1b2c3d4. Paths are not accepted.' }
$outputRoot = Join-Path $PSScriptRoot 'outputs'
$runDirectory = Join-Path $outputRoot $Run
if (-not (Test-Path -LiteralPath $runDirectory -PathType Container)) { throw "Run folder not found: $runDirectory" }
& docker compose -f (Join-Path $PSScriptRoot 'compose.yaml') run --rm --no-deps lab python -B -m c3lab verify "/output/$Run"
if ($LASTEXITCODE -ne 0) { throw 'Verification failed. Preserve the raw run and read validation_report.json.' }
& docker compose -f (Join-Path $PSScriptRoot 'compose.yaml') run --rm --no-deps lab python -B -m c3lab explain "/output/$Run"
if ($LASTEXITCODE -ne 0) { throw 'Evidence walkthrough failed. Keep the run and read its report.' }
