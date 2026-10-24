[CmdletBinding()]
param(
    [Alias('DryRun','CheckOnly')][switch]$Preflight,
    [switch]$Start,
    [switch]$Resume,
    [switch]$Cancel,
    [switch]$RetryFailed,
    [string]$Output,
    [string]$DockerStoragePath,
    [double]$SafetyFactor = 2,
    [int]$PlannedCopies = 2,
    [double]$ReserveGiB = 2,
    [double]$DockerReserveGiB = 2,
    [string]$Python
)
$ErrorActionPreference = 'Stop'
$chosen = @($Preflight,$Start,$Resume,$Cancel | Where-Object { $_ })
if ($chosen.Count -gt 1) { throw 'Choose one of -Preflight, -Start, -Resume or -Cancel.' }
if (-not $Python) {
    $repoDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $candidate = Join-Path $repoDirectory '.venv/Scripts/python.exe'
    if (Test-Path -LiteralPath $candidate) { $Python = $candidate }
    else {
        $command = Get-Command python -ErrorAction SilentlyContinue
        if (-not $command) { throw 'Python 3.11+ is required for the host controller. Supply -Python with its executable path.' }
        $Python = $command.Source
    }
}
$arguments = @('-B','-m','runtime.launcher')
if ($Start) { $arguments += '--start' }
elseif ($Resume) { $arguments += '--resume' }
elseif ($Cancel) { $arguments += '--cancel' }
else { $arguments += '--preflight' }
if ($Output) { $arguments += @('--output',$Output) }
if ($DockerStoragePath) { $arguments += @('--docker-storage-path',$DockerStoragePath) }
if ($RetryFailed) { $arguments += '--retry-failed' }
$arguments += @('--safety-factor',$SafetyFactor.ToString([Globalization.CultureInfo]::InvariantCulture),
                '--planned-copies',$PlannedCopies.ToString(),
                '--reserve-gib',$ReserveGiB.ToString([Globalization.CultureInfo]::InvariantCulture),
                '--docker-reserve-gib',$DockerReserveGiB.ToString([Globalization.CultureInfo]::InvariantCulture))
Push-Location -LiteralPath $PSScriptRoot
try {
    & $Python @arguments
    $collectionExitCode = $LASTEXITCODE
}
finally { Pop-Location }
exit $collectionExitCode
