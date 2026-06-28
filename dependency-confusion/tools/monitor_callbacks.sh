#!/usr/bin/env bash
# monitor_callbacks.sh — RASTTHACK AI Security Research
# Start interactsh listener and log all hits to a timestamped file
#
# Usage:
#   chmod +x monitor_callbacks.sh
#   ./monitor_callbacks.sh
#   ./monitor_callbacks.sh --token YOUR_INTERACTSH_TOKEN  # for self-hosted

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

LOGDIR="./callback_logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="${LOGDIR}/hits_${TIMESTAMP}.log"

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║  monitor_callbacks.sh — RASTTHACK Research   ║"
echo "║  Dependency Confusion — Callback Monitor     ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Check dependencies ───────────────────────────────────────────────────────

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}[ERROR] '$1' not found.${NC}"
        echo -e "        Install with: $2"
        exit 1
    fi
}

check_dep "interactsh-client" "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# ─── Setup log directory ──────────────────────────────────────────────────────

mkdir -p "$LOGDIR"
echo -e "${GREEN}[*] Log file: ${LOGFILE}${NC}"
echo -e "${GREEN}[*] Starting interactsh listener...${NC}\n"

# Write header to log
cat >> "$LOGFILE" <<EOF
# RASTTHACK — Dependency Confusion Callback Log
# Session started: $(date)
# ──────────────────────────────────────────────────
EOF

# ─── Parse args ───────────────────────────────────────────────────────────────

TOKEN_ARG=""
if [[ "${1:-}" == "--token" && -n "${2:-}" ]]; then
    TOKEN_ARG="-token ${2}"
fi

# ─── Start listener ───────────────────────────────────────────────────────────

echo -e "${YELLOW}[*] Listening for DNS/HTTP callbacks. Press Ctrl+C to stop.${NC}"
echo -e "${YELLOW}[*] Your interactsh URL will appear below:${NC}\n"

interactsh-client -v $TOKEN_ARG 2>&1 | tee -a "$LOGFILE" | while IFS= read -r line; do
    # Highlight DNS hits
    if echo "$line" | grep -qi "dns"; then
        echo -e "${RED}${BOLD}[DNS HIT]${NC} $line"
    # Highlight HTTP hits
    elif echo "$line" | grep -qi "http"; then
        echo -e "${GREEN}${BOLD}[HTTP HIT]${NC} $line"
        # Try to decode base64 data parameter if present
        DATA=$(echo "$line" | grep -oP '(?<=data=)[A-Za-z0-9+/=]+' || true)
        if [[ -n "$DATA" ]]; then
            DECODED=$(echo "$DATA" | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "$DATA")
            echo -e "${CYAN}  [DECODED DATA]:${NC}"
            echo "$DECODED" | sed 's/^/  /'
            echo "  [DECODED]: $DECODED" >> "$LOGFILE"
        fi
    else
        echo "$line"
    fi
done

echo -e "\n${CYAN}[*] Session ended. Log saved to: ${LOGFILE}${NC}"
