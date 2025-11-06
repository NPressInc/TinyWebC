#!/usr/bin/env bash
set -euo pipefail

# TinyWeb Tailscale setup helper
# Usage (non-interactive):
#   TS_AUTHKEY=tskey-xxxx TS_HOSTNAME=my-node TS_TAGS=tag:tinyweb-node ./scripts/setup_tailscale.sh
# Usage (interactive fallback):
#   ./scripts/setup_tailscale.sh

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

OS_ID=""; OS_VER="";
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID=${ID:-}
  OS_VER=${VERSION_ID:-}
fi

echo "Installing Tailscale..."
if command -v tailscale >/dev/null 2>&1 && command -v tailscaled >/dev/null 2>&1; then
  echo "Tailscale already installed. Skipping install."
else
  # Official installer covers most distros (Debian/Ubuntu/Raspbian/Alpine/Fedora/etc.)
  curl -fsSL https://tailscale.com/install.sh | sh
fi

echo "Enabling tailscaled service..."
systemctl enable --now tailscaled

# Read inputs from env or defaults
TS_AUTHKEY=${TS_AUTHKEY:-}
TS_HOSTNAME=${TS_HOSTNAME:-$(hostname -s)}
TS_TAGS=${TS_TAGS:-}
TS_ACCEPT_DNS=${TS_ACCEPT_DNS:-true}
TS_SSH=${TS_SSH:-true}
TS_EXTRA_ARGS=${TS_EXTRA_ARGS:-}

echo "Bringing up Tailscale..."
UP_CMD=(tailscale up --hostname="${TS_HOSTNAME}" --accept-dns="${TS_ACCEPT_DNS}" ${TS_EXTRA_ARGS})

if [[ -n "${TS_TAGS}" ]]; then
  UP_CMD+=(--advertise-tags="${TS_TAGS}")
fi
if [[ "${TS_SSH}" == "true" ]]; then
  UP_CMD+=(--ssh)
fi

if [[ -n "${TS_AUTHKEY}" ]]; then
  UP_CMD+=(--authkey="${TS_AUTHKEY}")
  # Non-interactive bring-up
  "${UP_CMD[@]}" || {
    echo "Failed to bring up Tailscale with provided auth key." >&2
    exit 1
  }
else
  echo "No TS_AUTHKEY provided. Falling back to interactive login..."
  echo "A URL will be printed to approve this device in your browser."
  "${UP_CMD[@]}" || true
fi

echo "Tailscale status:"
tailscale status || true

echo "\nTailscale setup complete."
echo "Hostname: ${TS_HOSTNAME}"
tailscale ip -4 || true
tailscale ip -6 || true


