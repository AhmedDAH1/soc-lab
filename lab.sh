#!/bin/sh
# One command for the whole lab: create the shared webhook secret on first
# run, build every service from its GitHub release and start everything.
#
#   ./lab.sh           run every attack straight away and check that the
#                      alerts arrived in SOAR-Lite (this is what CI runs)
#   ./lab.sh --watch   start everything but hold the attacks: you start each
#                      one from the live console and watch it go through
set -e
cd "$(dirname "$0")"

CONSOLE=http://localhost:8080
WATCH=0
case "${1:-}" in
    --watch|watch) WATCH=1 ;;
    "") ;;
    *) echo "Usage: ./lab.sh [--watch]"; exit 2 ;;
esac

if [ ! -f .env ]; then
    echo "WEBHOOK_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
    echo "Created .env with a new webhook secret."
fi

ai_hint() {
    if [ -z "${TRIAGE_PROVIDER}${TRIAGE_BASE_URL}" ] && ! grep -qE '^TRIAGE_(PROVIDER|BASE_URL)=.+' .env 2>/dev/null; then
        echo "AI triage is off. See \"AI triage\" in README.md to turn it on."
    fi
}

if [ "$WATCH" = 1 ]; then
    LAB_STEP=1 docker compose up --build -d
    echo
    echo "Everything is running and nothing has attacked yet."
    echo "Live console: $CONSOLE   (start each step there and watch it)"
    echo "SOAR-Lite:    http://localhost:8000"
    ai_hint
    echo "Stop with: docker compose down"
    # Open the console in the browser where that is possible (macOS, Linux desktop)
    if command -v open >/dev/null 2>&1; then open "$CONSOLE" 2>/dev/null || true
    elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$CONSOLE" >/dev/null 2>&1 || true
    fi
    exit 0
fi

LAB_STEP=0 docker compose up --build -d
echo "Waiting for the scan, the detections and the incidents..."
python3 verify.py
echo
echo "Live console: $CONSOLE   (what just happened, step by step; run any step again)"
echo "Dashboard:    http://localhost:8000"
echo "Analyze logs: http://localhost:8000/analyze   (upload your own logs and emails)"
ai_hint
echo "Stop with: docker compose down"
