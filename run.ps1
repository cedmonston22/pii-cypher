# Starts the PII Scrubber locally.
#
# Key material is generated once into .env.local and reused on every later run.
# That file is gitignored. Deleting it makes every existing job permanently
# unreadable, because PII_MASTER_KEY is what wraps each job's data key.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".env.local")) {
    Write-Host "Generating key material into .env.local (first run)" -ForegroundColor Yellow
    $master = python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
    $lookup = python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
    @("PII_MASTER_KEY=$master", "PII_LOOKUP_SECRET=$lookup") | Out-File -FilePath ".env.local" -Encoding utf8
}

foreach ($line in Get-Content ".env.local") {
    if ($line -match '^\s*([A-Z_]+)=(.+)$') {
        Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
    }
}

Write-Host ""
Write-Host "  PII Scrubber -> http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Sample files are in .\samples\"
Write-Host "  Ctrl+C to stop."
Write-Host ""

python -m uvicorn web.app:app --port 8000
