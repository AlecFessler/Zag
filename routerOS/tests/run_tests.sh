#!/bin/bash
# Run the full e2e test suite.
# Usage: sudo ./routerOS/tests/run_tests.sh [pytest args...]
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

echo "=== Building RouterOS ==="
cd "$REPO_ROOT/routerOS"
zig build

echo ""
echo "=== Building main project ==="
cd "$REPO_ROOT"
zig build -Dprofile=router

echo ""
echo "=== Running E2E Tests ==="
cd "$SCRIPT_DIR"
"$PYTEST" "$@" -v --tb=short
