#!/bin/bash
# Run kernel performance benchmarks sequentially.
# Each benchmark gets its own QEMU boot. Results are captured from
# [PERF] and [PROF] lines on serial output.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMEOUT=120
QEMU_CMD="qemu-system-x86_64 -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd -serial stdio -display none -no-reboot -enable-kvm -cpu host,+invtsc -machine q35 -device intel-iommu,intremap=off -net none -smp cores=4"

IMG_DIR="$ZAG_ROOT/zig-out/img"
BIN_DIR="$SCRIPT_DIR/bin"
RESULTS_DIR="$SCRIPT_DIR/perf_results"
mkdir -p "$RESULTS_DIR"

# Build all test ELFs
echo "Building test ELFs..."
cd "$SCRIPT_DIR"
zig build

# Create placeholder root_service.elf for kernel build
first_elf=$(find "$BIN_DIR" -name 'perf_*.elf' | head -1)
if [ -z "$first_elf" ]; then
    echo "No perf_*.elf files found. Build failed?"
    exit 1
fi
cp "$first_elf" "$BIN_DIR/root_service.elf"

# Build kernel
echo "Building kernel..."
cd "$ZAG_ROOT"
zig build -Dprofile=test
echo ""

run_one_bench() {
    local elf="$1"
    local name=$(basename "$elf" .elf)

    echo "--- $name ---"

    local workdir=$(mktemp -d)
    mkdir -p "$workdir/efi/boot"
    ln -s "$IMG_DIR/efi/boot/BOOTX64.EFI" "$workdir/efi/boot/"
    ln -s "$IMG_DIR/kernel.elf" "$workdir/"
    cp "$IMG_DIR/NvVars" "$workdir/" 2>/dev/null || true
    cp "$elf" "$workdir/root_service.elf"

    local output
    output=$(timeout "$TIMEOUT" $QEMU_CMD -drive "file=fat:rw:$workdir,format=raw" 2>/dev/null || true)

    # Extract [PERF] and [PROF] lines
    local perf_lines
    perf_lines=$(echo "$output" | grep -E '^\[PERF\]|\[PROF\]' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' || true)

    if [ -z "$perf_lines" ]; then
        echo "  (no output)"
    else
        echo "$perf_lines" | while IFS= read -r line; do
            echo "  $line"
        done
        echo "$perf_lines" >> "$RESULTS_DIR/latest.txt"
    fi

    # Check for [PASS]/[FAIL] (profiler test emits these)
    local result_line
    result_line=$(echo "$output" | grep -m1 '\[PASS\]\|\[FAIL\]' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' || true)
    if [ -n "$result_line" ]; then
        echo "  $result_line"
    fi

    rm -rf "$workdir"
    echo ""
}

# Collect perf test ELFs, sorted
mapfile -t perf_elfs < <(find "$BIN_DIR" -name 'perf_*.elf' | sort)
total=${#perf_elfs[@]}

if [ "$total" -eq 0 ]; then
    echo "No performance tests found."
    exit 0
fi

# Clear previous results
> "$RESULTS_DIR/latest.txt"

echo "Running $total performance benchmarks (sequential)..."
echo ""

for elf in "${perf_elfs[@]}"; do
    run_one_bench "$elf"
done

echo "================================"
echo "Results written to: $RESULTS_DIR/latest.txt"
echo "Total benchmarks: $total"
