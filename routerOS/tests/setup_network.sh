#!/bin/bash
# Setup TAP interfaces and WAN simulator services for e2e testing.
# Run with sudo.
set -euo pipefail

echo "=== RouterOS E2E Test Network Setup ==="

# ── TAP interfaces ──────────────────────────────────────────────────
echo "Setting up TAP interfaces..."

if ! ip link show tap0 &>/dev/null; then
    ip tuntap add dev tap0 mode tap user "${SUDO_USER:-$USER}"
    ip addr add 10.0.2.1/24 dev tap0
    ip link set tap0 up
    echo "  tap0 created (WAN: 10.0.2.1/24)"
else
    echo "  tap0 already exists"
fi

if ! ip link show tap1 &>/dev/null; then
    ip tuntap add dev tap1 mode tap user "${SUDO_USER:-$USER}"
    ip addr add 192.168.1.50/24 dev tap1
    ip link set tap1 up
    echo "  tap1 created (LAN: 192.168.1.50/24)"
else
    echo "  tap1 already exists"
fi

# ── IP forwarding ───────────────────────────────────────────────────
echo "Enabling IP forwarding..."
sysctl -q net.ipv4.ip_forward=1

echo ""
echo "=== Setup complete ==="
echo "TAP interfaces ready. Run tests with:"
echo "  cd $(dirname "$0")/../.. && routerOS/tests/.venv/bin/pytest routerOS/tests/ -v"
