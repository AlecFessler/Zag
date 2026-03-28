#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Binding x550 to vfio-pci ==="
"$SCRIPT_DIR/vfio-bind.sh"

SERIAL_LOG="/tmp/x550_passthrough_serial.log"

echo ""
echo "=== Launching QEMU with x550 passthrough ==="
echo "(Ctrl-C to stop)"
echo "Serial log: $SERIAL_LOG"
echo ""

qemu-system-x86_64 \
    -m 1G \
    -bios /usr/share/ovmf/x64/OVMF.4m.fd \
    -drive file=fat:rw:"$REPO_ROOT/zig-out/img",format=raw \
    -serial file:"$SERIAL_LOG" \
    -display none \
    -enable-kvm -cpu host,+invtsc \
    -machine q35 \
    -net none \
    -device pcie-root-port,id=rp1,slot=1 \
    -device pcie-pci-bridge,id=br1,bus=rp1 \
    -device vfio-pci,host=05:00.0,bus=br1,addr=1.0 \
    -device vfio-pci,host=05:00.1,bus=br1,addr=2.0 \
    -smp cores=4 &
QEMU_PID=$!

# Tail the serial log, stripping ANSI escape codes
sleep 1
tail -f "$SERIAL_LOG" 2>/dev/null | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' &
TAIL_PID=$!

# Wait for QEMU to exit (Ctrl-C kills it)
trap "kill $QEMU_PID $TAIL_PID 2>/dev/null; wait $QEMU_PID 2>/dev/null" INT TERM
wait $QEMU_PID 2>/dev/null
EXIT=$?
kill $TAIL_PID 2>/dev/null

echo ""
echo "QEMU exited with code: $EXIT"
echo "Full serial log: $SERIAL_LOG"

echo ""
echo "=== Restoring ixgbe ==="
"$SCRIPT_DIR/vfio-unbind.sh"

exit $EXIT
