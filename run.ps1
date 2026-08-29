# Starts the PII Scrubber locally.
#
# The vault and its key material live in the per-user application data
# directory, not in this checkout. `python cli.py status` prints where.
#
# Key generation is `cli.py init`'s job and nowhere else. This script used to
# generate whenever .env.local was absent, which is the wrong condition: a
# fresh clone next to an existing vault minted a new master key and made every
# job in that vault permanently unreadable. init refuses when a vault it
# cannot read is present.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# A checkout that has not been migrated still keeps its keys here. The
# environment wins over the key file, so sourcing this keeps such an install
# working until `python cli.py migrate` moves it.
if (Test-Path ".env.local") {
    foreach ($line in Get-Content ".env.local") {
        if ($line -match '^\s*([A-Z_]+)=(.+)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
        }
    }
}

python cli.py init --quiet
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "  PII Scrubber -> http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Sample files are in .\samples\"
Write-Host "  Ctrl+C to stop."
Write-Host ""

python -m uvicorn web.app:app --port 8000
