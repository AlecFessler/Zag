#!/bin/bash
# Run a specific list of test ELFs in parallel.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMEOUT=15
# Default to a single QEMU instance to keep agent runs from blowing up RAM.
# Override interactively with `PARALLEL=4 bash run_some.sh ...` for fast local runs.
PARALLEL="${PARALLEL:-1}"
QEMU_CMD="qemu-system-x86_64 -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd -serial stdio -display none -no-reboot -enable-kvm -cpu host,+invtsc -machine q35 -device intel-iommu,intremap=off -net none -smp cores=4"

IMG_DIR="$ZAG_ROOT/zig-out/img"
BIN_DIR="$SCRIPT_DIR/bin"
RESULTS_DIR=$(mktemp -d)

run_one_test() {
    local elf="$1"
    local name=$(basename "$elf" .elf)
    local workdir=$(mktemp -d)
    mkdir -p "$workdir/efi/boot"
    ln -s "$IMG_DIR/efi/boot/BOOTX64.EFI" "$workdir/efi/boot/"
    ln -s "$IMG_DIR/kernel.elf" "$workdir/"
    cp "$IMG_DIR/NvVars" "$workdir/" 2>/dev/null || true
    cp "$elf" "$workdir/root_service.elf"
    local output
    output=$(timeout "$TIMEOUT" $QEMU_CMD -drive "file=fat:rw:$workdir,format=raw" 2>/dev/null || true)
    local result
    result=$(echo "$output" | grep -m1 '\[PASS\]\|\[FAIL\]\|\[SKIP\]' || true)
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

test_elfs=()
for name in "$@"; do
    test_elfs+=("$BIN_DIR/$name.elf")
done

printf '%s\n' "${test_elfs[@]}" | xargs -n1 -P"$PARALLEL" -I{} bash -c 'run_one_test "$@"' _ {}

pass=0
fail=0
skip=0
for r in "$RESULTS_DIR"/*; do
    line=$(cat "$r")
    echo "$line"
    if echo "$line" | grep -q '\[PASS\]'; then
        pass=$((pass+1))
    elif echo "$line" | grep -q '\[SKIP\]'; then
        skip=$((skip+1))
    else
        fail=$((fail+1))
    fi
done
echo "Pass: $pass  Skip: $skip  Fail: $fail"
rm -rf "$RESULTS_DIR"
