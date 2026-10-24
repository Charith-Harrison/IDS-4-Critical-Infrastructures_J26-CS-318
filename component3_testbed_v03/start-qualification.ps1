[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$SkipBuild,
    [switch]$RetryFailed,
    [ValidatePattern('^(All|EQ0[1-9]|EQ1[0-4])$')][string]$RunId = 'All'
)
$ErrorActionPreference = 'Stop'
$labDirectory = $PSScriptRoot
$composePath = Join-Path $labDirectory 'compose.yaml'
$outputDirectory = [IO.Path]::GetFullPath((Join-Path $labDirectory '../component3_collection_runs/engineering-v03'))
$evidenceDirectory = Join-Path $labDirectory 'evidence'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker is unavailable.' }
$engine = & docker info --format '{{.OSType}}'
if ($LASTEXITCODE -ne 0 -or ($engine | Out-String).Trim() -ne 'linux') { throw 'Docker Linux engine is required.' }
& docker compose -f $composePath config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose configuration did not validate.' }
$roster = (Get-Content -LiteralPath (Join-Path $labDirectory 'design/proposed_run_roster.json') -Raw | ConvertFrom-Json).engineering_runs
$requested = if ($RunId -eq 'All') { @(1..14 | ForEach-Object { 'EQ{0:d2}' -f $_ }) } else { @($RunId) }
foreach ($qid in $requested) {
    $row = @($roster | Where-Object planned_run_id -eq $qid)
    if ($row.Count -ne 1 -or $row[0].purpose -ne 'ENGINEERING_ONLY_UNSCORED') {
        throw "Unsupported qualification configuration: $qid"
    }
}
Write-Host 'Loopback-only Docker qualification. No host ports, main collection or model work.'
if ($CheckOnly) {
    Write-Host ('CHECK ONLY passed for ' + ($requested -join ', ') + '. No build, capture or output writes.')
    return
}
New-Item -ItemType Directory -Path $outputDirectory,$evidenceDirectory -Force | Out-Null
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$transcriptPath = Join-Path $evidenceDirectory ('execution-' + $stamp + '.log')
$executionPath = Join-Path $evidenceDirectory ('execution-' + $stamp + '.json')
$commands = New-Object 'System.Collections.Generic.List[object]'
$execution = [ordered]@{
    purpose = 'ENGINEERING_V03_UNSCORED_NOT_MODEL_DATA'
    requested = $requested
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    status = 'STARTED'
    commands = $commands
    host_script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    collector_machine = $env:COMPUTERNAME
    collector_user = $env:USERNAME
    host_os = [Environment]::OSVersion.VersionString
    host_timezone = (Get-TimeZone).Id
    clock_record = [DateTimeOffset]::Now.ToString('o')
    clock_note = 'Host self-report; no independent clock or hardware attestation'
    no_model_preprocessing_or_training = $true
}
function Invoke-LabDocker([string[]]$Arguments) {
    $commandRecord = [ordered]@{argv = @('docker') + $Arguments; started_at_utc = [DateTime]::UtcNow.ToString('o')}
    $commands.Add($commandRecord)
    & docker @Arguments
    $code = $LASTEXITCODE
    $commandRecord['exit_code'] = $code
    if ($code -ne 0) { throw ('Docker command failed with code ' + $code + ': ' + ($Arguments -join ' ')) }
}
Start-Transcript -LiteralPath $transcriptPath | Out-Null
try {
    foreach ($qid in $requested) {
        $existing = @(Get-ChildItem -LiteralPath $outputDirectory -Directory | Where-Object Name -Like ($qid + '-*'))
        if ($existing.Count) {
            $passed = @($existing | Where-Object {
                $v = Join-Path $_.FullName 'validation_report.json'
                (Test-Path -LiteralPath $v) -and ((Get-Content -LiteralPath $v -Raw | ConvertFrom-Json).status -eq 'PASSED')
            })
            if ($passed.Count -or -not $RetryFailed) { throw "Existing $qid recording found. Preserve it; use verification. -RetryFailed is only for documented failed attempts." }
        }
    }
    $baseText = Invoke-LabDocker -Arguments @('image','inspect','--format','{{json .}}','c3-qualification:0.2.0')
    $execution['base_image'] = ($baseText | Out-String | ConvertFrom-Json)
    if (-not $SkipBuild) {
        Invoke-LabDocker -Arguments @('compose','-f',$composePath,'build','--pull=false','qualification')
    }
    $imageText = Invoke-LabDocker -Arguments @('image','inspect','--format','{{json .}}','c3-qualification:0.3.0')
    $image = $imageText | Out-String | ConvertFrom-Json
    $execution['image'] = $image
    $execution['docker_version'] = ((Invoke-LabDocker -Arguments @('version','--format','{{json .}}')) | Out-String | ConvertFrom-Json)
    $execution['compose_version'] = ((Invoke-LabDocker -Arguments @('compose','version','--short')) | Out-String).Trim()
    $imageSourcesText = Invoke-LabDocker -Arguments @('compose','-f',$composePath,'run','--rm','--no-deps','qualification','python','-B','-m','c3qual','identity')
    $imageSources = $imageSourcesText | Out-String | ConvertFrom-Json
    foreach ($property in $imageSources.PSObject.Properties) {
        $localPath = [IO.Path]::GetFullPath((Join-Path $labDirectory $property.Name))
        if (-not $localPath.StartsWith($labDirectory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe image source path.' }
        if ((Get-FileHash -LiteralPath $localPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $property.Value) {
            throw ('Image/local source mismatch: ' + $property.Name + '. Rebuild before collection.')
        }
    }
    $execution['image_source_sha256'] = $imageSources
    Write-Host 'Running offline tests inside the actual qualification image.'
    Invoke-LabDocker -Arguments @('compose','-f',$composePath,'run','--rm','--no-deps','qualification','python','-B','-m','unittest','discover','-s','tests','-v')
    foreach ($qid in $requested) {
        $before = @(Get-ChildItem -LiteralPath $outputDirectory -Directory | ForEach-Object Name)
        $exit = 1
        try {
            Write-Host "Collecting one unscored qualification recording: $qid"
            Invoke-LabDocker -Arguments @('compose','-f',$composePath,'run','--rm','--no-deps','qualification','python','-B','-m','c3qual','run','--output','/output','--planned-run',$qid)
            $exit = 0
        }
        finally {
            $fresh = @(Get-ChildItem -LiteralPath $outputDirectory -Directory | Where-Object { $_.Name -notin $before })
            if ($fresh.Count -eq 1) {
                $hostRecord = [ordered]@{
                    purpose = 'ENGINEERING_V03_UNSCORED_NOT_MODEL_DATA'
                    planned_run_id = $qid
                    collector_machine = $execution['collector_machine']
                    collector_user = $execution['collector_user']
                    host_os = $execution['host_os']
                    host_timezone = $execution['host_timezone']
                    clock_record = [DateTimeOffset]::Now.ToString('o')
                    clock_note = $execution['clock_note']
                    docker_version = $execution['docker_version']
                    compose_version = $execution['compose_version']
                    docker_exit_code = $exit
                    image = $image
                    base_image = $execution['base_image']
                    image_source_sha256 = $imageSources
                    execution_ledger = $executionPath
                    host_script_sha256 = $execution['host_script_sha256']
                    recorded_at_utc = [DateTime]::UtcNow.ToString('o')
                    note = 'Real software testbed capture; no attestation of industrial campaign independence.'
                }
                $hostRecord | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $fresh[0].FullName 'host_execution.json') -Encoding UTF8
                Write-Host ('Preserved run folder: ' + $fresh[0].FullName)
            }
        }
    }
    $execution['status'] = 'PASSED'
}
catch {
    $execution['status'] = 'FAILED'
    $execution['error'] = $_.Exception.Message
    throw
}
finally {
    $execution['ended_at_utc'] = [DateTime]::UtcNow.ToString('o')
    $execution | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath $executionPath -Encoding UTF8
    Stop-Transcript | Out-Null
}
Write-Host 'Qualification complete. Review the evidence; main collection remains disabled.'
