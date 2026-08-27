#!/usr/bin/env bash
# Starts the PII Scrubber locally. See run.ps1 for the PowerShell equivalent.
#
# Key material is generated once into .env.local and reused. Deleting that file
# makes every existing job permanently unreadable.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env.local ]; then
  echo "Generating key material into .env.local (first run)"
  {
    echo "PII_MASTER_KEY=$(python -c 'import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
    echo "PII_LOOKUP_SECRET=$(python -c 'import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
  } > .env.local
fi

set -a; . ./.env.local; set +a

echo
echo "  PII Scrubber -> http://127.0.0.1:8000"
echo "  Sample files are in ./samples/"
echo "  Ctrl+C to stop."
echo
exec python -m uvicorn web.app:app --port 8000
