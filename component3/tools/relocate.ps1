$ErrorActionPreference = 'Stop'
$c3Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$c3Record = Get-Content -LiteralPath (Join-Path $c3Root 'component3/reports/preservation.json') -Raw | ConvertFrom-Json
foreach ($c3Move in $c3Record.moves) {
    $c3Source = [IO.Path]::GetFullPath((Join-Path $c3Root $c3Move.before))
    $c3Target = [IO.Path]::GetFullPath((Join-Path $c3Root $c3Move.after))
    foreach ($c3Path in @($c3Source, $c3Target)) {
        if (-not $c3Path.StartsWith($c3Root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Path escapes repository: $c3Path"
        }
    }
    if (-not (Test-Path -LiteralPath $c3Source -PathType Container)) { throw "Missing source: $c3Source" }
    if (Test-Path -LiteralPath $c3Target) { throw "Destination exists: $c3Target" }
    foreach ($c3File in $c3Move.files.PSObject.Properties) {
        $c3Input = Join-Path $c3Source $c3File.Name
        if ((Get-FileHash -LiteralPath $c3Input -Algorithm SHA256).Hash.ToLowerInvariant() -ne $c3File.Value.sha256) {
            throw "Changed since snapshot: $c3Input"
        }
    }
}
foreach ($c3Move in $c3Record.moves) {
    $c3Source = [IO.Path]::GetFullPath((Join-Path $c3Root $c3Move.before))
    $c3Target = [IO.Path]::GetFullPath((Join-Path $c3Root $c3Move.after))
    New-Item -ItemType Directory -Path (Split-Path -Parent $c3Target) -Force | Out-Null
    Move-Item -LiteralPath $c3Source -Destination $c3Target
    Write-Output "$($c3Move.before) -> $($c3Move.after)"
}
