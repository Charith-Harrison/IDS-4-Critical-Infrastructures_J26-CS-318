# Stop the Component 2 demo server (if Ctrl+C was not used). Usage:
#   powershell -ExecutionPolicy Bypass -File .\stop_c2_demo.ps1
param([int]$Port = 8020)
$conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if (-not $conns) { Write-Host "Nothing is listening on port $Port."; exit 0 }
$conns | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
    Stop-Process -Id $_ -Force
    Write-Host "Stopped process $_ (port $Port)."
}
