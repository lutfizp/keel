$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $py (Join-Path $PSScriptRoot "keel_mcp.py") @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
