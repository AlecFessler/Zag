#!/bin/bash
# Run kernel test suite with per-assertion QEMU isolation.
# Each assertion gets its own QEMU boot. Tests run in parallel.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMEOUT=30
# Default to a single QEMU instance to keep agent runs from blowing up RAM.
# Override interactively with `PARALLEL=16 bash run_tests.sh` for fast local runs.
PARALLEL="${PARALLEL:-1}"
QEMU_CMD="qemu-system-x86_64 -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd -serial stdio -display none -no-reboot -enable-kvm -cpu host,+invtsc -machine q35 -device intel-iommu,intremap=off -net none -smp cores=4"

# Verify spec coverage before running tests
echo "Verifying spec/test coverage..."
if ! python3 "$SCRIPT_DIR/verify_coverage.py"; then
    echo "ABORT: Spec/test mismatch. Fix before running tests."
    exit 1
fi
echo ""

IMG_DIR="$ZAG_ROOT/zig-out/img"
BIN_DIR="$SCRIPT_DIR/bin"
RESULTS_DIR=$(mktemp -d)

# Build all test ELFs
echo "Building test ELFs..."
cd "$SCRIPT_DIR"
zig build 2>/dev/null

# Create placeholder root_service.elf for kernel build
first_elf=$(find "$BIN_DIR" -name 's*.elf' | head -1)
cp "$first_elf" "$BIN_DIR/root_service.elf"

# Build kernel (creates zig-out/img/ with kernel.elf, efi/, etc.)
echo "Building kernel..."
cd "$ZAG_ROOT"
zig build -Dprofile=test 2>/dev/null
echo ""

run_one_test() {
    local elf="$1"
    local name=$(basename "$elf" .elf)
    local workdir=$(mktemp -d)

    # Set up FAT image directory
    mkdir -p "$workdir/efi/boot"
    ln -s "$IMG_DIR/efi/boot/BOOTX64.EFI" "$workdir/efi/boot/"
    ln -s "$IMG_DIR/kernel.elf" "$workdir/"
    cp "$IMG_DIR/NvVars" "$workdir/" 2>/dev/null || true
    cp "$elf" "$workdir/root_service.elf"

    # Run QEMU, capture serial output
    local output
    output=$(timeout "$TIMEOUT" $QEMU_CMD -drive "file=fat:rw:$workdir,format=raw" 2>/dev/null || true)

    # Extract result line
    local result
    result=$(echo "$output" | grep -m1 '\[PASS\]\|\[FAIL\]' || true)
    # Strip ANSI escape codes
    result=$(echo "$result" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g')

    if [ -z "$result" ]; then
        echo "[FAIL] $name (no output)" > "$RESULTS_DIR/$name"
    else
        echo "$result" > "$RESULTS_DIR/$name"
    fi

    rm -rf "$workdir"
}

export -f run_one_test
export IMG_DIR TIMEOUT QEMU_CMD RESULTS_DIR

# Collect all test ELFs, sorted
mapfile -t test_elfs < <(find "$BIN_DIR" -name 's*.elf' | sort)
total=${#test_elfs[@]}

echo "Running $total tests ($PARALLEL parallel)..."
echo ""

# Run in parallel
printf '%s\n' "${test_elfs[@]}" | xargs -P "$PARALLEL" -I{} bash -c 'run_one_test "$@"' _ {}

# Aggregate results
pass=0
fail=0
failures=""

for f in $(ls "$RESULTS_DIR"/ | sort); do
    result=$(cat "$RESULTS_DIR/$f")
    if echo "$result" | grep -q '\[PASS\]'; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        failures="$failures\n  $result"
    fi
done

rm -rf "$RESULTS_DIR"

echo "================================"
echo "Total: $pass pass, $fail fail out of $((pass + fail))"
if [ "$fail" -eq 0 ]; then
    echo "All tests passed!"
else
    echo -e "Failures:$failures"
fi

exit $( [ "$fail" -eq 0 ] && echo 0 || echo 1 )
