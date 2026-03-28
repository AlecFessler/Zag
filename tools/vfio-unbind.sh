#!/usr/bin/env bash
set -euo pipefail

echo "=== Restoring x550-T2 to ixgbe driver ==="

for dev in 0000:05:00.0 0000:05:00.1; do
    echo "  Unbinding $dev from vfio-pci..."
    echo "$dev" > /sys/bus/pci/devices/$dev/driver/unbind 2>/dev/null || true
    echo "" > /sys/bus/pci/devices/$dev/driver_override
done

if [ -e /sys/bus/pci/devices/0000:04:00.0/driver ]; then
    echo "  Unbinding PCIe switch 0000:04:00.0..."
    echo 0000:04:00.0 > /sys/bus/pci/devices/0000:04:00.0/driver/unbind
else
    echo "  PCIe switch 0000:04:00.0 already unbound"
fi
echo "" > /sys/bus/pci/devices/0000:04:00.0/driver_override 2>/dev/null || true

echo "  Rescanning PCI bus..."
echo 1 > /sys/bus/pci/rescan

echo ""
echo "=== Current driver bindings ==="
for dev in 0000:04:00.0 0000:05:00.0 0000:05:00.1; do
    driver=$(basename $(readlink /sys/bus/pci/devices/$dev/driver 2>/dev/null) 2>/dev/null || echo "none")
    echo "  $dev -> $driver"
done

echo ""
echo "Done."
