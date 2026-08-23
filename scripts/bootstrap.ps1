$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
if ($env:PYTHON) {
    & $env:PYTHON scripts/bootstrap.py @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 scripts/bootstrap.py @args
} else {
    & python scripts/bootstrap.py @args
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
