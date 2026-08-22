$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $py scripts/bootstrap.py @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
