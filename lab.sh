#!/bin/sh
# One command for the whole lab: create the shared webhook secret on first
# run, build every service from its GitHub release, start everything, and
# check that the alerts arrived in SOAR-Lite.
set -e
cd "$(dirname "$0")"

if [ ! -f .env ]; then
    echo "WEBHOOK_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
    echo "Created .env with a new webhook secret."
fi

docker compose up --build -d
echo "Waiting for the scan, the detections and the incidents..."
python3 verify.py
echo
echo "Dashboard:    http://localhost:8000"
echo "Analyze logs: http://localhost:8000/analyze   (upload your own logs and emails)"
if [ -z "${TRIAGE_PROVIDER}${TRIAGE_BASE_URL}" ] && ! grep -qE '^TRIAGE_(PROVIDER|BASE_URL)=.+' .env 2>/dev/null; then
    echo "AI triage is off. See \"AI triage\" in README.md to turn it on."
fi
echo "Stop with: docker compose down"
