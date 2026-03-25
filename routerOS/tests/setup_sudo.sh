#!/bin/bash
# Setup network namespaces and permissions for e2e tests that need root.
# Run with: sudo ./routerOS/tests/setup_sudo.sh
#
# Creates a "lan" network namespace with a macvlan on tap1.
# Traffic from this namespace must route through the router (192.168.1.1)
# to reach the WAN side, which is what we need for NAT/forwarding tests.
set -euo pipefail

USER_HOME="${SUDO_USER:+$(eval echo ~$SUDO_USER)}"
REPO="${USER_HOME:-$HOME}/Zag"

echo "=== RouterOS E2E sudo setup ==="

# ── Clean up any leftover state ─────────────────────────────────────
ip netns del lan_test 2>/dev/null || true
ip link del lan-test0 2>/dev/null || true

# ── Create LAN test namespace ───────────────────────────────────────
# This namespace has a macvlan on tap1 and can only reach the WAN
# through the router at 192.168.1.1 (no direct path to tap0).
echo "Creating lan_test namespace..."
ip netns add lan_test

# Create macvlan on tap1 for the namespace
ip link add lan-test0 link tap1 type macvlan mode bridge
ip link set lan-test0 address 02:00:00:00:00:20
ip link set lan-test0 netns lan_test

# Configure the interface inside the namespace
ip netns exec lan_test ip link set lo up
ip netns exec lan_test ip link set lan-test0 up
# Use .60 to avoid conflict with host's .50 on tap1
ip netns exec lan_test ip addr add 192.168.1.60/24 dev lan-test0
ip netns exec lan_test ip route add default via 192.168.1.1
ip netns exec lan_test ip -6 addr add fd00:lan::60/64 dev lan-test0 2>/dev/null || true

# ── Allow non-root to use raw sockets on tap interfaces ─────────────
# (scapy needs this for packet injection)
setcap cap_net_raw,cap_net_admin+eip "$REPO/routerOS/tests/.venv/bin/python3" 2>/dev/null || \
    echo "Warning: setcap failed — scapy tests may need sudo"

# ── Allow passwordless sudo for test namespace commands ─────────────
SUDOERS_FILE="/etc/sudoers.d/zag-e2e-tests"
REAL_USER="${SUDO_USER:-$USER}"
cat > "$SUDOERS_FILE" <<EOF
# Allow routerOS e2e tests to run commands in the lan_test namespace
$REAL_USER ALL=(root) NOPASSWD: /usr/bin/ip netns exec lan_test *
$REAL_USER ALL=(root) NOPASSWD: /usr/bin/ip netns list
$REAL_USER ALL=(root) NOPASSWD: /usr/bin/tcpdump *
$REAL_USER ALL=(root) NOPASSWD: /usr/bin/kill *
$REAL_USER ALL=(root) NOPASSWD: $REPO/routerOS/tests/.venv/bin/python3 *
EOF
chmod 0440 "$SUDOERS_FILE"
echo "Added sudoers rules for $REAL_USER in $SUDOERS_FILE"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Namespace 'lan_test' created with:"
echo "  Interface: lan-test0 (macvlan on tap1)"
echo "  MAC:       02:00:00:00:00:20"
echo "  IP:        192.168.1.60/24"
echo "  Gateway:   192.168.1.1 (router)"
echo ""
echo "Run tests with:"
echo "  cd $REPO && routerOS/tests/.venv/bin/pytest routerOS/tests/ -v"
echo ""
echo "To clean up: sudo ip netns del lan_test"
