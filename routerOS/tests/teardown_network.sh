#!/bin/bash
# Tear down TAP interfaces and test network.
# Run with sudo.
set -euo pipefail

echo "=== RouterOS E2E Test Network Teardown ==="

# Remove sudoers entry
rm -f /etc/sudoers.d/zag-e2e-tests 2>/dev/null && echo "  Removed sudoers rules" || true

# Remove test namespace
ip netns del lan_test 2>/dev/null && echo "  Removed lan_test namespace" || true
ip link del lan-test0 2>/dev/null || true

# Remove any macvlan test interfaces
for dev in $(ip -o link show type macvlan 2>/dev/null | grep "test-" | awk -F: '{print $2}' | tr -d ' '); do
    echo "  Removing macvlan: $dev"
    ip link del "$dev" 2>/dev/null || true
done

# Remove TAP interfaces
if ip link show tap0 &>/dev/null; then
    ip link del tap0
    echo "  tap0 removed"
fi

if ip link show tap1 &>/dev/null; then
    ip link del tap1
    echo "  tap1 removed"
fi

echo "=== Teardown complete ==="
