const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 128;

pub fn run(perm_view_addr: u64) void {
    t.section("grant_perm (S2.4, S4)");
    testGrantInvalidSource();
    testGrantInvalidTarget();
    testGrantNonProcessTarget();
    testGrantTargetNoGrantTo();
    testDeviceInPermView(perm_view_addr);
    testGrantVmReservationNotGrantable();
    testDeviceGrantNoDeviceOwn(perm_view_addr);
    testDeviceExclusiveTransfer(perm_view_addr);
}

fn findDeviceHandle(perm_view_addr: u64) ?u64 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) return entry.handle;
    }
    return null;
}

fn testGrantInvalidSource() void {
    const rc = syscall.grant_perm(99999, 0, 0b1111);
    t.expectEqual("S4.grant_perm: invalid src_handle returns E_BADCAP", -3, rc);
}

fn testGrantInvalidTarget() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle <= 0) { t.fail("setup failed"); return; }
    const rc = syscall.grant_perm(@intCast(shm_handle), 99999, 0b1111);
    t.expectEqual("S4.grant_perm: invalid target_proc_handle returns E_BADCAP", -3, rc);
}

fn testGrantNonProcessTarget() void {
    const shm1 = syscall.shm_create(syscall.PAGE4K);
    const shm2 = syscall.shm_create(syscall.PAGE4K);
    if (shm1 <= 0 or shm2 <= 0) { t.fail("setup failed"); return; }
    const rc = syscall.grant_perm(@intCast(shm1), @intCast(shm2), 0b1111);
    t.expectEqual("S4.grant_perm: target must be a process handle", -3, rc);
}

fn testGrantTargetNoGrantTo() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle <= 0) { t.fail("setup failed"); return; }
    const child_elf = embedded.child_exit;
    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) { t.fail("proc_create failed"); return; }
    const grant_rights = (perms.SharedMemoryRights{
        .read = true, .write = true, .grant = true,
    }).bits();
    const rc = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);
    t.expectEqual("S2.3: target must have grant_to right", -2, rc);
    t.waitForCleanup(@intCast(proc_handle));
}

fn testDeviceInPermView(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var found = false;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            found = true;
            break;
        }
    }
    if (found) {
        t.pass("S2.1: device_region entry visible in user view with metadata");
    } else {
        t.fail("S2.1: no device_region entry found in user view");
    }
}

fn testGrantVmReservationNotGrantable() void {
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.grant_perm(@intCast(vm_result.val), 0, 0b11);
    t.expectEqual("S2.3: VM reservation handles are not grantable (E_INVAL)", -1, rc);
}

fn testDeviceGrantNoDeviceOwn(perm_view_addr: u64) void {
    const dev_handle = findDeviceHandle(perm_view_addr) orelse {
        t.fail("no device handle"); return;
    };
    const child_elf = embedded.child_exit;
    const child_rights = (perms.ProcessRights{
        .grant_to = true, .spawn_thread = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) { t.fail("proc_create failed"); return; }
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true }).bits();
    const rc = syscall.grant_perm(dev_handle, @intCast(proc_handle), dev_rights);
    t.expectEqual("S2.3: device grant requires target has device_own (E_PERM)", -2, rc);
    t.waitForCleanup(@intCast(proc_handle));
}

fn testDeviceExclusiveTransfer(perm_view_addr: u64) void {
    const dev_handle = findDeviceHandle(perm_view_addr) orelse {
        t.fail("no device handle for exclusive transfer test"); return;
    };
    const child_elf = embedded.child_exit;
    const child_rights = (perms.ProcessRights{
        .grant_to = true, .spawn_thread = true, .device_own = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) { t.fail("proc_create failed"); return; }
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true }).bits();
    const rc = syscall.grant_perm(dev_handle, @intCast(proc_handle), dev_rights);
    if (rc != 0) { t.failWithVal("device grant failed", 0, rc); return; }
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var still_has_device = false;
    for (view) |*entry| {
        if (entry.handle == dev_handle and entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            still_has_device = true;
            break;
        }
    }
    if (!still_has_device) {
        t.pass("S2.3: device grant is exclusive, removed from source");
    } else {
        t.fail("S2.3: device handle still in source after grant");
    }
    t.waitForCleanup(@intCast(proc_handle));
}
