#!/bin/bash
# Setup TAP interfaces and WAN simulator services for e2e testing.
# Run with sudo.
set -euo pipefail

echo "=== RouterOS E2E Test Network Setup ==="

# ── Remove stale passthrough IP from eno1 if present ────────────────
# The passthrough tests add 10.0.2.1/24 to eno1; this conflicts with tap0
if ip addr show eno1 2>/dev/null | grep -q "10.0.2.1/24"; then
    ip addr del 10.0.2.1/24 dev eno1 2>/dev/null || true
    echo "  Removed stale 10.0.2.1/24 from eno1"
fi

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
    ip addr add 10.1.1.50/24 dev tap1
    ip link set tap1 up
    echo "  tap1 created (LAN: 10.1.1.50/24)"
else
    echo "  tap1 already exists"
fi

# ── IPv6 addresses ─────────────────────────────────────────────────
echo "Adding IPv6 addresses..."
ip -6 addr add fd00:wan::1/64 dev tap0 2>/dev/null || true
ip -6 addr add fd00:lan::50/64 dev tap1 2>/dev/null || true

# NOTE: ip_forward is NOT enabled here — the router inside QEMU handles
# forwarding. Enabling it on the host can break the host's DNS resolution.

echo ""
echo "=== Setup complete ==="
echo "TAP interfaces ready. Run tests with:"
echo "  cd $(dirname "$0")/../.. && routerOS/tests/.venv/bin/pytest routerOS/tests/ -v"
