param(
    [ValidateSet('test','verify','prepare','train','freeze','evaluate-final')][string]$Stage='verify',
    [string]$Python,
    [string]$DependencyPath,
    [string]$Source,
    [string]$Artifacts
)
$ErrorActionPreference='Stop'
if (-not $Python) {
    $c3Venv = Join-Path $PSScriptRoot '..\..\.venv-c3\Scripts\python.exe'
    if (Test-Path -LiteralPath $c3Venv) { $Python=$c3Venv }
    else { $Python=(Get-Command python -ErrorAction Stop).Source }
}
$c3OldPath=$env:PYTHONPATH
try {
    $c3Paths=@($PSScriptRoot)
    if ($DependencyPath) { $c3Paths=@($DependencyPath)+$c3Paths }
    if ($c3OldPath) { $c3Paths+=$c3OldPath }
    $env:PYTHONPATH=$c3Paths -join [IO.Path]::PathSeparator
    if ($Stage -eq 'test') { & $Python -B -m unittest discover -s (Join-Path $PSScriptRoot 'tests') -v }
    else {
        $c3Args=@('-B','-m','c3model',$Stage)
        if ($Source) { $c3Args+=@('--source',$Source) }
        if ($Artifacts) { $c3Args+=@('--artifacts',$Artifacts) }
        & $Python @c3Args
    }
    if ($LASTEXITCODE -ne 0) { throw "Stage $Stage failed (exit $LASTEXITCODE)" }
} finally { $env:PYTHONPATH=$c3OldPath }
