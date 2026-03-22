const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 64;

pub fn run(perm_view_addr: u64) void {
    t.section("mmio_map + mmio_unmap (S2.3, S2.13)");
    testMmioMapUnmap(perm_view_addr);
    testMmioMapInvalidDevice();
    testMmioMapNoMmioRight(perm_view_addr);
    testMmioUnmapNotFound(perm_view_addr);
}

fn findDeviceHandle(perm_view_addr: u64) ?u64 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) return entry.handle;
    }
    return null;
}

fn testMmioMapUnmap(perm_view_addr: u64) void {
    const dev_handle = findDeviceHandle(perm_view_addr) orelse {
        t.fail("no device handle in perm view"); return;
    };
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const vm_handle: u64 = @intCast(vm_result.val);
    const map_rc = syscall.mmio_map(dev_handle, vm_handle, 0);
    if (map_rc != 0) { t.failWithVal("mmio_map failed", 0, map_rc); return; }
    t.pass("S2.3.mmio_map: device mapped with uncacheable attributes");
    const unmap_rc = syscall.mmio_unmap(dev_handle, vm_handle);
    t.expectEqual("S2.3.mmio_unmap: unbinds MMIO mapping", 0, unmap_rc);
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
    const dev_handle = findDeviceHandle(perm_view_addr) orelse {
        t.fail("no device handle"); return;
    };
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.mmio_map(dev_handle, @intCast(vm_result.val), 0);
    t.expectEqual("S4.mmio_map: mmio/R/W not in max_rights returns E_PERM", -2, rc);
}

fn testMmioUnmapNotFound(perm_view_addr: u64) void {
    const dev_handle = findDeviceHandle(perm_view_addr) orelse {
        t.fail("no device handle"); return;
    };
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .mmio = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.mmio_unmap(dev_handle, @intCast(vm_result.val));
    t.expectEqual("S4.mmio_unmap: no prior map returns E_NOENT", -10, rc);
}
