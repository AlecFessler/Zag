const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 128;

pub fn run(perm_view_addr: u64) void {
    t.section("device enumeration + mmio + ioport (S2.13, S4)");
    testDevicesPresent(perm_view_addr);
    testSerialPortPresent(perm_view_addr);
    testMmioMapUnmap(perm_view_addr);
    testMmioMapInvalidDevice();
    testMmioMapNoMmioRight(perm_view_addr);
    testMmioUnmapNotFound(perm_view_addr);
    testMmioMapPortIoDevice(perm_view_addr);
    testIoportReadSerial(perm_view_addr);
    testIoportWriteReadScratch(perm_view_addr);
    testIoportBadHandle();
    testIoportBadWidth(perm_view_addr);
    testIoportBadOffset(perm_view_addr);
    testIoportReadWidth2(perm_view_addr);
    testDmaMapBadHandle();
    testDmaMapPortIoDevice(perm_view_addr);
    testDeviceDump(perm_view_addr);
}

fn getView(addr: u64) *const [MAX_PERMS]pv.UserViewEntry {
    return @ptrFromInt(addr);
}

fn findMmioDevice(perm_view_addr: u64) ?*const pv.UserViewEntry {
    const view = getView(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and entry.deviceType() == 0) return entry;
    }
    return null;
}

fn findSerialDevice(perm_view_addr: u64) ?*const pv.UserViewEntry {
    const view = getView(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and entry.deviceClass() == @intFromEnum(perms.DeviceClass.serial)) return entry;
    }
    return null;
}

fn testDevicesPresent(perm_view_addr: u64) void {
    const view = getView(perm_view_addr);
    var device_count: u32 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) device_count += 1;
    }
    if (device_count > 0) {
        t.pass("S2.9: firmware enumeration found devices in perm view");
    } else {
        t.fail("S2.9: no device handles found after enumeration");
    }
}

fn testSerialPortPresent(perm_view_addr: u64) void {
    if (findSerialDevice(perm_view_addr)) |entry| {
        if (entry.deviceType() == @intFromEnum(perms.DeviceType.port_io)) {
            t.pass("S2.9: serial port detected as port_io device");
        } else {
            t.fail("S2.9: serial port has wrong device_type");
        }
    } else {
        t.fail("S2.9: no serial port found in device enumeration");
    }
}

fn testMmioMapUnmap(perm_view_addr: u64) void {
    const dev_entry = findMmioDevice(perm_view_addr) orelse {
        t.fail("no MMIO device for map/unmap test"); return;
    };
    const dev_size: u64 = dev_entry.deviceSizeOrPortCount();
    const map_size = if (dev_size > 0) ((dev_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K else syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, map_size, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const vm_handle: u64 = @intCast(vm_result.val);
    const map_rc = syscall.mmio_map(dev_entry.handle, vm_handle, 0);
    if (map_rc != 0) { t.failWithVal("mmio_map failed", 0, map_rc); return; }
    t.pass("S2.2.mmio_map: PCI device mapped into reservation");
    const unmap_rc = syscall.mmio_unmap(dev_entry.handle, vm_handle);
    t.expectEqual("S2.2.mmio_unmap: unbinds MMIO mapping", 0, unmap_rc);
}

fn testMmioMapInvalidDevice() void {
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.mmio_map(99999, @intCast(vm_result.val), 0);
    t.expectEqual("S4.mmio_map: invalid device handle returns E_BADCAP", -3, rc);
}

fn testMmioMapNoMmioRight(perm_view_addr: u64) void {
    const dev_entry = findMmioDevice(perm_view_addr) orelse {
        t.fail("no MMIO device"); return;
    };
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.mmio_map(dev_entry.handle, @intCast(vm_result.val), 0);
    t.expectEqual("S4.mmio_map: mmio/R/W not in max_rights returns E_PERM", -2, rc);
}

fn testMmioUnmapNotFound(perm_view_addr: u64) void {
    const dev_entry = findMmioDevice(perm_view_addr) orelse {
        t.fail("no MMIO device"); return;
    };
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.mmio_unmap(dev_entry.handle, @intCast(vm_result.val));
    t.expectEqual("S4.mmio_unmap: no prior map returns E_NOENT", -10, rc);
}

fn testMmioMapPortIoDevice(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device for port_io guard test"); return;
    };
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.mmio_map(serial_entry.handle, @intCast(vm_result.val), 0);
    t.expectEqual("S4.mmio_map: port_io device rejected for mmio_map (E_INVAL)", -1, rc);
}

fn testIoportReadSerial(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device for ioport_read test"); return;
    };
    const rc = syscall.ioport_read(serial_entry.handle, 5, 1);
    if (rc >= 0) {
        t.pass("S4.ioport_read: read serial LSR returns value");
    } else {
        t.failWithVal("S4.ioport_read: failed", 0, rc);
    }
}

fn testIoportWriteReadScratch(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device for scratch test"); return;
    };
    const write_rc = syscall.ioport_write(serial_entry.handle, 7, 1, 0xA5);
    if (write_rc != 0) { t.failWithVal("scratch write failed", 0, write_rc); return; }
    const read_rc = syscall.ioport_read(serial_entry.handle, 7, 1);
    if (read_rc == 0xA5) {
        t.pass("S4.ioport_write+read: scratch register round-trip works");
    } else {
        t.failWithVal("S4.ioport_write+read: scratch mismatch", 0xA5, read_rc);
    }
    _ = syscall.ioport_write(serial_entry.handle, 7, 1, 0x00);
}

fn testIoportBadHandle() void {
    const rc = syscall.ioport_read(99999, 0, 1);
    t.expectEqual("S4.ioport_read: invalid handle returns E_BADCAP", -3, rc);
}

fn testIoportBadWidth(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device"); return;
    };
    const rc = syscall.ioport_read(serial_entry.handle, 0, 3);
    t.expectEqual("S4.ioport_read: width=3 returns E_INVAL", -1, rc);
}

fn testIoportBadOffset(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device"); return;
    };
    const rc = syscall.ioport_read(serial_entry.handle, 100, 1);
    t.expectEqual("S4.ioport_read: offset > port_count returns E_INVAL", -1, rc);
}

fn testDmaMapBadHandle() void {
    const shm = syscall.shm_create(syscall.PAGE4K);
    if (shm <= 0) { t.fail("setup failed"); return; }
    const rc = syscall.dma_map(99999, @intCast(shm));
    if (rc == -3) {
        t.pass("S4.dma_map: invalid device handle returns E_BADCAP");
    } else if (rc == -2) {
        t.pass("S4.dma_map: no IOMMU returns E_PERM (expected without IOMMU)");
    } else {
        t.failWithVal("S4.dma_map: unexpected result", -3, rc);
    }
}

fn testDmaMapPortIoDevice(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device for dma test"); return;
    };
    const shm = syscall.shm_create(syscall.PAGE4K);
    if (shm <= 0) { t.fail("setup failed"); return; }
    const rc = syscall.dma_map(serial_entry.handle, @intCast(shm));
    if (rc == -1) {
        t.pass("S4.dma_map: port_io device rejected (E_INVAL)");
    } else if (rc == -2) {
        t.pass("S4.dma_map: no IOMMU returns E_PERM (expected without IOMMU)");
    } else {
        t.failWithVal("S4.dma_map: unexpected result for port_io", -1, rc);
    }
}

fn testIoportReadWidth2(perm_view_addr: u64) void {
    const serial_entry = findSerialDevice(perm_view_addr) orelse {
        t.fail("no serial device"); return;
    };
    const rc = syscall.ioport_read(serial_entry.handle, 0, 2);
    if (rc >= 0) {
        t.pass("S4.ioport_read: width=2 (word) succeeds on serial port");
    } else {
        t.failWithVal("S4.ioport_read: width=2 failed", 0, rc);
    }
}

fn testDeviceDump(perm_view_addr: u64) void {
    const view = getView(perm_view_addr);
    syscall.write("\n  == Device Dump ==\n");
    for (view) |*entry| {
        if (entry.entry_type != pv.ENTRY_TYPE_DEVICE_REGION) continue;
        const dtype = entry.deviceType();
        const dclass = entry.deviceClass();
        if (dtype == @intFromEnum(perms.DeviceType.mmio)) {
            syscall.write("  MMIO ");
        } else {
            syscall.write("  PIO  ");
        }
        printClass(dclass);
        syscall.write(" vendor=");
        t.printHex(entry.pciVendor());
        syscall.write(" device=");
        t.printHex(entry.pciDevice());
        syscall.write(" size=");
        t.printHex(entry.deviceSizeOrPortCount());
        syscall.write("\n");
    }
    t.pass("S2.9: device dump completed");
}

fn printClass(class: u8) void {
    switch (class) {
        @intFromEnum(perms.DeviceClass.network) => syscall.write("net    "),
        @intFromEnum(perms.DeviceClass.serial) => syscall.write("serial "),
        @intFromEnum(perms.DeviceClass.storage) => syscall.write("storage"),
        @intFromEnum(perms.DeviceClass.display) => syscall.write("display"),
        @intFromEnum(perms.DeviceClass.timer) => syscall.write("timer  "),
        @intFromEnum(perms.DeviceClass.usb) => syscall.write("usb    "),
        else => syscall.write("unknown"),
    }
}
