#!/bin/bash
# Run the full e2e test suite.
# Usage: sudo ./routerOS/tests/run_tests.sh [pytest args...]
# Requires: sudo (for raw sockets and network namespace)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$SCRIPT_DIR/.venv"
PYTEST="$VENV/bin/pytest"

if [ ! -f "$PYTEST" ]; then
    echo "Error: venv not found. Create it with:"
    echo "  python3 -m venv $VENV"
    echo "  $VENV/bin/pip install pexpect scapy pytest"
    exit 1
fi

echo "=== Clean Building RouterOS ==="
cd "$REPO_ROOT/routerOS"
rm -rf .zig-cache zig-out
sudo -u "${SUDO_USER:-$USER}" zig build

echo ""
echo "=== Clean Building main project ==="
cd "$REPO_ROOT"
rm -rf .zig-cache zig-out
sudo -u "${SUDO_USER:-$USER}" zig build -Dprofile=router

echo ""
echo "=== Killing stale QEMU ==="
pkill qemu-system-x86 2>/dev/null || true
sleep 1

# Clean up any leftover namespace (will be recreated by conftest)
ip netns del lan_test 2>/dev/null || true
ip link del lan-test0 2>/dev/null || true

# Remove root-owned NvVars if present
rm -f "$REPO_ROOT/zig-out/img/NvVars" 2>/dev/null || true

echo ""
echo "=== Running E2E Tests ==="
cd "$SCRIPT_DIR"
"$PYTEST" "$@" -v --tb=short
