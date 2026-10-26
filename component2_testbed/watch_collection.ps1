# Read-only live view of the final collection log. Ctrl-C to stop (the collection keeps running).
param([string]$Log = "$PSScriptRoot\data\final_v1.collect.log", [int]$Total = 384)
$start = $null
while ($true) {
    Clear-Host
    $lines = @()
    if (Test-Path $Log) { $lines = @(Get-Content $Log) }
    $done = @($lines | Where-Object { $_ -match ' collected ' }).Count
    $errs = @($lines | Where-Object { $_ -match 'collection_error|Traceback|Error' }).Count
    if ($null -eq $start -and $done -gt 0) { $start = Get-Date; $startDone = $done }
    $pct = [math]::Round(100 * $done / $Total, 1)
    $bar = ('#' * [int]($pct / 2.5)).PadRight(40, '.')
    Write-Host "Component 2 final collection (final_v1)  $(Get-Date -Format 'HH:mm:ss')"
    Write-Host ""
    Write-Host "  [$bar] $done / $Total runs ($pct %)"
    if ($start -and $done -gt $startDone) {
        $rate = ((Get-Date) - $start).TotalSeconds / ($done - $startDone)
        $eta = (Get-Date).AddSeconds($rate * ($Total - $done))
        Write-Host ("  ~{0:N0} s per run overall, ETA {1:HH:mm}" -f $rate, $eta)
    }
    $free = [math]::Round((Get-PSDrive D).Free / 1GB, 1)
    Write-Host "  Errors: $errs    Free on D: $free GB"
    Write-Host ""
    Write-Host "  Latest runs:"
    $lines | Select-Object -Last 8 | ForEach-Object { Write-Host "    $_" }
    if ($lines | Where-Object { $_ -match '^exit' }) { Write-Host ""; Write-Host "  Collection finished."; break }
    Start-Sleep -Seconds 15
}
