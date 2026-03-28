#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Defaults
TARGET="all"
PYTEST_K=""
PYTEST_FILE=""
ITERATIONS="100000"
SEED="42"

usage() {
    cat <<'EOF'
Usage: ./test.sh [target] [options]

Targets:
  kernel          Run kernel integration tests (QEMU)
  router          Run router integration tests (pytest)
  passthrough     Run x550 passthrough test (real hardware, requires sudo)
  kernel-fuzz     Run all kernel fuzzers (buddy, heap, vmm, rbt)
  router-fuzz     Run router packet processing fuzzer
  all             Run kernel + router tests (default)

Options:
  -h, --help        Show this help
  -k EXPR           Pass -k filter to pytest (router tests only)
  -f FILE           Run specific pytest file (router tests only)
  --iterations N    Fuzzer iteration count (default: 100000)
  --seed N          Fuzzer seed (default: 42)

Examples:
  ./test.sh                              # run all tests
  ./test.sh kernel                       # kernel tests only
  ./test.sh router -k test_dns           # router DNS tests only
  ./test.sh router -f test_nat.py        # single test file
  ./test.sh router-fuzz --iterations 50000 --seed 123
  ./test.sh passthrough                  # x550 real hardware test
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

run_kernel_tests() {
    echo "=== Kernel Tests ==="
    zig build run -Dprofile=test
}

run_router_tests() {
    ensure_network
    ensure_venv

    echo "=== Building RouterOS ==="
    (cd "$SCRIPT_DIR/routerOS" && zig build)
    zig build -Dprofile=router

    echo "=== Router Integration Tests ==="
    local pytest_args=("-v")
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

run_passthrough_test() {
    echo "=== X550 Passthrough Test ==="

    # 1. Build with x550 driver
    echo "Building routerOS with x550 driver..."
    (cd "$SCRIPT_DIR/routerOS" && zig build -Dnic=x550)
    zig build -Dprofile=router -Dnet=passthrough

    # 2. Bind x550 to vfio-pci
    echo "Binding x550 to vfio-pci..."
    sudo "$SCRIPT_DIR/tools/vfio-bind.sh"

    # 3. Set up Realtek as WAN mock gateway (x550 is owned by VM now)
    echo "Setting up Realtek as mock ISP gateway..."
    sudo ip addr add 10.0.2.1/24 dev eno1 2>/dev/null || true
    sudo ip link set eno1 up

    # 4. Start tcpdump on Realtek (WAN side) to capture forwarded traffic
    local PCAP="/tmp/x550_passthrough_test.pcap"
    echo "Starting tcpdump on eno1 (WAN side)..."
    sudo tcpdump -i eno1 -c 10 -w "$PCAP" udp port 9999 &
    local TCPDUMP_PID=$!

    # 5. Launch QEMU with passthrough
    echo "Launching QEMU with x550 passthrough..."
    local QEMU_LOG="/tmp/x550_passthrough_qemu.log"
    sudo timeout 60 qemu-system-x86_64 \
        -m 1G \
        -bios /usr/share/ovmf/x64/OVMF.4m.fd \
        -drive file=fat:rw:zig-out/img,format=raw \
        -serial file:/tmp/x550_passthrough_serial.log \
        -display none \
        -no-reboot \
        -enable-kvm -cpu host,+invtsc \
        -machine q35 \
        -net none \
        -device pcie-root-port,id=rp1,slot=1 \
        -device pcie-pci-bridge,id=br1,bus=rp1 \
        -device vfio-pci,host=05:00.0,bus=br1,addr=1.0 \
        -device vfio-pci,host=05:00.1,bus=br1,addr=2.0 \
        -smp cores=4 \
        > "$QEMU_LOG" 2>&1 &
    local QEMU_PID=$!

    # 6. Wait for router to boot (look for console banner in serial log)
    local SERIAL_LOG="/tmp/x550_passthrough_serial.log"
    echo "Waiting for router to boot..."
    local BOOTED=false
    for i in $(seq 1 30); do
        if sudo grep -q "load-config" "$SERIAL_LOG" 2>/dev/null; then
            BOOTED=true
            break
        fi
        sleep 1
    done

    if ! $BOOTED; then
        echo "FAIL: Router did not boot within 30s"
        echo "=== Serial log ==="
        sudo cat "$SERIAL_LOG" 2>/dev/null || echo "(empty)"
        echo "=== QEMU log ==="
        cat "$QEMU_LOG" 2>/dev/null || echo "(empty)"
        sudo kill $QEMU_PID 2>/dev/null || true
        sudo kill $TCPDUMP_PID 2>/dev/null || true
        sudo "$SCRIPT_DIR/tools/vfio-unbind.sh"
        exit 1
    fi
    echo "Router booted."

    # 7. Wait for traffic to flow through (tcpdump captures or timeout)
    echo "Waiting up to 30s for UDP traffic on WAN side..."
    local TRAFFIC=false
    for i in $(seq 1 30); do
        if ! kill -0 $TCPDUMP_PID 2>/dev/null; then
            # tcpdump exited — it captured its 10 packets
            TRAFFIC=true
            break
        fi
        sleep 1
    done

    # 8. Cleanup
    sudo kill $QEMU_PID 2>/dev/null || true
    sudo kill $TCPDUMP_PID 2>/dev/null || true
    wait $QEMU_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true

    echo "Restoring ixgbe driver..."
    sudo "$SCRIPT_DIR/tools/vfio-unbind.sh"

    # 9. Report results
    echo ""
    if $TRAFFIC; then
        echo "PASS: Captured UDP traffic on WAN side"
        sudo tcpdump -r "$PCAP" 2>/dev/null | head -5
    else
        echo "FAIL: No UDP traffic captured on WAN side within 30s"
        echo "=== Serial log (last 30 lines) ==="
        sudo tail -30 "$SERIAL_LOG" 2>/dev/null || echo "(empty)"
        exit 1
    fi
}

# ── Dispatch ──────────────────────────────────────────────────────────

case "$TARGET" in
    kernel)
        run_kernel_tests
        ;;
    router)
        run_router_tests
        ;;
    passthrough)
        run_passthrough_test
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
