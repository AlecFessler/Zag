#!/bin/bash
# Boot a PoC ELF as root_service under QEMU, print serial output.
# Usage: ./run.sh <poc-source.zig>
set -e

if [ -z "$1" ]; then
    echo "usage: $0 <poc-source.zig>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC="$1"

cd "$SCRIPT_DIR"

# PoCs that spawn a child use @embedFile("zig-out/bin/child"); the child
# source is named in a `// CHILD: <name>.zig` directive at the top of the
# PoC. Forward it to the build as -Dchild=<name>.zig so build.zig also
# compiles the child ELF.
CHILD=$(awk '/^\/\/ CHILD:/ { print $3; exit }' "$SRC")
if [ -n "$CHILD" ]; then
    zig build "-Dsrc=$SRC" "-Dchild=$CHILD" 2>&1
else
    zig build "-Dsrc=$SRC" 2>&1
fi

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

mkdir -p "$WORKDIR/efi/boot"
cp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTX64.EFI" "$WORKDIR/efi/boot/"
cp "$ZAG_ROOT/zig-out/img/kernel.elf" "$WORKDIR/"
cp "$ZAG_ROOT/zig-out/img/NvVars" "$WORKDIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/zig-out/bin/poc" "$WORKDIR/root_service.elf"

timeout 60 qemu-system-x86_64 \
    -m 2G \
    -bios /usr/share/ovmf/x64/OVMF.4m.fd \
    -serial stdio \
    -display none \
    -no-reboot \
    -enable-kvm \
    -cpu host,+invtsc \
    -machine q35 \
    -device intel-iommu,intremap=off \
    -net none \
    -smp cores=4 \
    -drive "file=fat:rw:$WORKDIR,format=raw" 2>/dev/null || true
