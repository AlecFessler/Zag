#!/usr/bin/env bash
set -euo pipefail

echo "=== Binding x550-T2 to vfio-pci for QEMU passthrough ==="

modprobe vfio-pci

# All devices in the IOMMU group must be unbound/bound together:
# 04:00.0 = AMD PCIe switch (upstream of x550)
# 05:00.0 = x550 port 0 (LAN)
# 05:00.1 = x550 port 1 (WAN)

for dev in 0000:05:00.0 0000:05:00.1; do
    echo "  Unbinding $dev from current driver..."
    echo "$dev" > /sys/bus/pci/devices/$dev/driver/unbind 2>/dev/null || true
    echo vfio-pci > /sys/bus/pci/devices/$dev/driver_override
    echo "$dev" > /sys/bus/pci/drivers/vfio-pci/bind
    echo "  Bound $dev to vfio-pci"
done

# PCIe switch just needs to be unbound (no driver is fine for VFIO group)
# PCIe switch just needs to be unbound (no driver is fine for VFIO group)
if [ -e /sys/bus/pci/devices/0000:04:00.0/driver ]; then
    echo "  Unbinding PCIe switch 0000:04:00.0..."
    echo 0000:04:00.0 > /sys/bus/pci/devices/0000:04:00.0/driver/unbind
else
    echo "  PCIe switch 0000:04:00.0 already unbound"
fi

echo ""
echo "=== VFIO groups ==="
ls -la /dev/vfio/

echo ""
echo "Done. Run QEMU with: zig build run -Dprofile=router -Dnet=passthrough"
