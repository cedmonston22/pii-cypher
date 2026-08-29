#!/usr/bin/env bash
# Starts the PII Scrubber locally. See run.ps1 for the PowerShell equivalent.
#
# The vault and its key material live in the per-user application data
# directory, not in this checkout. `python cli.py status` prints where.
#
# Key generation is `cli.py init`'s job and nowhere else. This script used to
# generate whenever .env.local was absent, which is the wrong condition: a
# fresh clone next to an existing vault minted a new master key and made every
# job in that vault permanently unreadable. init refuses when a vault it
# cannot read is present.
set -euo pipefail
cd "$(dirname "$0")"

# A checkout that has not been migrated still keeps its keys here. The
# environment wins over the key file, so sourcing this keeps such an install
# working until `python cli.py migrate` moves it.
if [ -f .env.local ]; then
  set -a; . ./.env.local; set +a
fi

python cli.py init --quiet

echo
echo "  PII Scrubber -> http://127.0.0.1:8000"
echo "  Sample files are in ./samples/"
echo "  Ctrl+C to stop."
echo
exec python -m uvicorn web.app:app --port 8000
