#!/bin/bash

# TinyWeb Tailscale health check
# ---------------------------------
# Verifies that:
#   1. The tailscale CLI is available
#   2. The local node reports BackendState "Running" and is online
#   3. (Optional) A MagicDNS/peer host is reachable via ping
#
# Usage:
#   tailscale_health_check.sh [--timeout <seconds>] [--ping-host <host>]
#
# Environment overrides:
#   TAILSCALE_BIN                 Path to the tailscale CLI (default: tailscale)
#   TAILSCALE_HEALTHCHECK_HOST    Hostname/IP to ping when --ping-host not supplied
#
set -euo pipefail

TIMEOUT=5
PING_HOST="${TAILSCALE_HEALTHCHECK_HOST:-}" 
TAILSCALE_BIN="${TAILSCALE_BIN:-tailscale}"

usage() {
  cat <<USAGE
TinyWeb Tailscale health check

Options:
  --timeout <seconds>    Ping timeout (default: ${TIMEOUT})
  --ping-host <host>     Hostname/IP to ping (overrides env)
  -h, --help             Show this help text
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      if [[ $# -lt 2 ]]; then
        echo "Error: --timeout requires a value" >&2
        exit 2
      fi
      TIMEOUT="$2"
      shift 2
      ;;
    --ping-host)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ping-host requires a value" >&2
        exit 2
      fi
      PING_HOST="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v "$TAILSCALE_BIN" >/dev/null 2>&1; then
  echo "tailscale binary not found (tried '$TAILSCALE_BIN')" >&2
  exit 1
fi

# Capture status JSON. Using python for robust parsing without jq dependency.
STATUS_JSON="$($TAILSCALE_BIN status --json 2>/dev/null)"
if [[ -z "$STATUS_JSON" ]]; then
  echo "tailscale status --json returned no output" >&2
  exit 1
fi

read -r BACKEND_STATE ONLINE <<<"$(python3 - <<'PYCODE'
import json, sys
try:
    data = json.load(sys.stdin)
    backend = data.get("BackendState", "")
    online = data.get("Self", {}).get("Online", False)
    sys.stdout.write(f"{backend} {int(bool(online))}")
except Exception as exc:
    sys.stderr.write(f"failed to parse tailscale status JSON: {exc}\n")
    sys.exit(1)
PYCODE
" <<<"$STATUS_JSON")

if [[ -z "$BACKEND_STATE" ]]; then
  echo "Unable to determine tailscale backend state" >&2
  exit 1
fi

if [[ "$BACKEND_STATE" != "Running" ]]; then
  echo "tailscale backend not running (state: $BACKEND_STATE)" >&2
  exit 1
fi

if [[ "$ONLINE" != "1" ]]; then
  echo "tailscale reports node offline" >&2
  exit 1
fi

if [[ -n "$PING_HOST" ]]; then
  if ! ping -c1 -W"$TIMEOUT" "$PING_HOST" >/dev/null 2>&1; then
    echo "tailscale ping to $PING_HOST failed" >&2
    exit 1
  fi
fi

echo "tailscale healthcheck passed"
exit 0

