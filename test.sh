#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Defaults
TARGET="all"
PYTEST_K=""
PYTEST_FILE=""
FAIL_FAST=""
ITERATIONS="100000"
SEED="42"

usage() {
    cat <<'EOF'
Usage: ./test.sh [target] [options]

Targets:
  kernel          Run kernel integration tests (QEMU)
  router          Run router integration tests (pytest)
  kernel-fuzz     Run all kernel fuzzers (buddy, heap, vmm, rbt)
  router-fuzz     Run router packet processing fuzzer
  all             Run kernel + router tests (default)

Options:
  -h, --help        Show this help
  -k EXPR           Pass -k filter to pytest (router tests only)
  -f FILE           Run specific pytest file (router tests only)
  -x                Exit after first test failure (router tests only)
  --iterations N    Fuzzer iteration count (default: 100000)
  --seed N          Fuzzer seed (default: 42)

Examples:
  ./test.sh                              # run all tests
  ./test.sh kernel                       # kernel tests only
  ./test.sh router -k test_dns           # router DNS tests only
  ./test.sh router -f test_nat.py        # single test file
  ./test.sh router-fuzz --iterations 50000 --seed 123
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────

# First positional arg is the target (if it doesn't start with -)
if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
    TARGET="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -k)
            PYTEST_K="$2"
            shift 2
            ;;
        -f)
            PYTEST_FILE="$2"
            shift 2
            ;;
        -x)
            FAIL_FAST="-x"
            shift
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# ── Network setup (router/router-fuzz/all) ───────────────────────────

ensure_network() {
    if ! ip link show tap0 &>/dev/null || ! ip link show tap1 &>/dev/null; then
        echo "tap0/tap1 not found — running network setup (requires sudo)..."
        sudo "$SCRIPT_DIR/routerOS/tests/setup_network.sh"
    fi
}

ensure_venv() {
    local venv="$SCRIPT_DIR/routerOS/tests/.venv"
    if [[ ! -d "$venv" ]]; then
        echo "Creating Python venv for router tests..."
        python3 -m venv "$venv"
        "$venv/bin/pip" install --quiet pytest pexpect
    fi
}

# ── Test runners ──────────────────────────────────────────────────────

clean_nvvars() {
    # Remove OVMF NvVars if root-owned (leftover from sudo passthrough tests)
    local nv="$SCRIPT_DIR/zig-out/img/NvVars"
    if [[ -f "$nv" ]] && [[ "$(stat -c %U "$nv" 2>/dev/null)" == "root" ]]; then
        rm -f "$nv"
    fi
}

run_kernel_tests() {
    echo "=== Kernel Tests ==="
    clean_nvvars
    zig build run -Dprofile=test
}

run_router_tests() {
    ensure_network
    ensure_venv

    echo "=== Building RouterOS ==="
    (cd "$SCRIPT_DIR/routerOS" && zig build -Dnic=e1000)
    zig build -Dprofile=router
    clean_nvvars

    echo "=== Router Integration Tests ==="
    local pytest_args=("-v")
    if [[ -n "$FAIL_FAST" ]]; then
        pytest_args+=("-x")
    fi
    if [[ -n "$PYTEST_K" ]]; then
        pytest_args+=("-k" "$PYTEST_K")
    fi
    if [[ -n "$PYTEST_FILE" ]]; then
        pytest_args+=("$SCRIPT_DIR/routerOS/tests/$PYTEST_FILE")
    else
        pytest_args+=("$SCRIPT_DIR/routerOS/tests/")
    fi
    "$SCRIPT_DIR/routerOS/tests/.venv/bin/pytest" "${pytest_args[@]}"
}

run_kernel_fuzzers() {
    local fuzz_args=("--" "-s" "$SEED" "-i" "$ITERATIONS")
    local fuzzers=(buddy_allocator heap_allocator vmm red_black_tree)

    for fuzzer in "${fuzzers[@]}"; do
        echo "=== Fuzzing: $fuzzer ==="
        (cd "$SCRIPT_DIR/fuzzing/$fuzzer" && zig build fuzz "${fuzz_args[@]}")
    done
}

run_router_fuzzer() {
    echo "=== Router Fuzzer ==="
    (cd "$SCRIPT_DIR/fuzzing/router" && zig build run -- -s "$SEED" -i "$ITERATIONS")
}

# ── Dispatch ──────────────────────────────────────────────────────────

case "$TARGET" in
    kernel)
        run_kernel_tests
        ;;
    router)
        run_router_tests
        ;;
    kernel-fuzz)
        run_kernel_fuzzers
        ;;
    router-fuzz)
        run_router_fuzzer
        ;;
    all)
        run_kernel_tests
        run_router_tests
        ;;
    *)
        echo "Unknown target: $TARGET"
        usage
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
