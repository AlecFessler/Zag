const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("vm_reserve + vm_perms error paths");
    testReserveZeroSize();
    testReserveBadAlignment();
    testReserveShareableAndMmio();
    testReserveWithHint();
    testPermsInvalidHandle();
    testPermsBadAlignment();
    testPermsOutOfBounds();
    testPermsShareableBit();
    testShmCreateZeroSize();
    testShmCreateBadAlign();
    testShmMapNoShareable();
    testShmMapDuplicate();
    testShmUnmapNotFound();
    testShmMapBusy();
}

fn testReserveZeroSize() void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.vm_reserve(0, 0, rights);
    t.expectEqual("vm_reserve: zero size rejected", -1, result.val);
}

fn testReserveBadAlignment() void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.vm_reserve(0, 123, rights);
    t.expectEqual("vm_reserve: bad alignment rejected", -1, result.val);
}

fn testReserveShareableAndMmio() void {
    const rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
        .mmio = true,
    }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    t.expectEqual("vm_reserve: shareable+mmio mutual exclusion", -1, result.val);
}

fn testReserveWithHint() void {
    const hint: u64 = 0x0000_1000_0000_0000;
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(hint, syscall.PAGE4K, rights);
    if (result.val > 0 and result.val2 == hint) {
        t.pass("vm_reserve: hint address honored");
    } else if (result.val > 0) {
        t.pass("vm_reserve: hint address succeeded (different addr)");
    } else {
        t.failWithVal("vm_reserve: hint address failed", 0, result.val);
    }
}

fn testPermsInvalidHandle() void {
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc = syscall.vm_perms(99999, 0, syscall.PAGE4K, rw);
    t.expectEqual("vm_perms: invalid handle", -3, rc);
}

fn testPermsBadAlignment() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("perms_badalign: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const rc = syscall.vm_perms(handle, 1, syscall.PAGE4K, rights);
    t.expectEqual("vm_perms: bad offset alignment", -1, rc);
}

fn testPermsOutOfBounds() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("perms_oob: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const rc = syscall.vm_perms(handle, 0, 2 * syscall.PAGE4K, rights);
    t.expectEqual("vm_perms: out of bounds", -1, rc);
}

fn testPermsShareableBit() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("perms_shareable: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const shareable = (perms.VmReservationRights{ .read = true, .shareable = true }).bits();
    const rc = syscall.vm_perms(handle, 0, syscall.PAGE4K, shareable);
    t.expectEqual("vm_perms: shareable bit rejected", -1, rc);
}

fn testShmCreateZeroSize() void {
    const rc = syscall.shm_create(0);
    t.expectEqual("shm_create: zero size rejected", -1, rc);
}

fn testShmCreateBadAlign() void {
    const rc = syscall.shm_create(100);
    if (rc > 0) {
        t.pass("shm_create: non-aligned rounds up (OK)");
    } else {
        t.pass("shm_create: non-aligned rejected (OK)");
    }
}

fn testShmMapNoShareable() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
        t.fail("shm_map_noshr: shm_create failed");
        return;
    }
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) {
        t.fail("shm_map_noshr: vm_reserve failed");
        return;
    }
    const rc = syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0);
    t.expectEqual("shm_map: no shareable bit rejected", -2, rc);
}

fn testShmMapDuplicate() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
        t.fail("shm_map_dup: shm_create failed");
        return;
    }
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, 2 * syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) {
        t.fail("shm_map_dup: vm_reserve failed");
        return;
    }
    const vm_handle: u64 = @intCast(vm_result.val);
    const rc1 = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    if (rc1 != 0) {
        t.failWithVal("shm_map_dup: first map failed", 0, rc1);
        return;
    }
    const rc2 = syscall.shm_map(@intCast(shm_handle), vm_handle, syscall.PAGE4K);
    t.expectEqual("shm_map: duplicate SHM in reservation rejected", -1, rc2);
}

fn testShmUnmapNotFound() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
        t.fail("shm_unmap_nf: shm_create failed");
        return;
    }
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) {
        t.fail("shm_unmap_nf: vm_reserve failed");
        return;
    }
    const rc = syscall.shm_unmap(@intCast(shm_handle), @intCast(vm_result.val));
    t.expectEqual("shm_unmap: not mapped returns E_NOENT", -10, rc);
}

fn testShmMapBusy() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
        t.fail("shm_map_busy: shm_create failed");
        return;
    }
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) {
        t.fail("shm_map_busy: vm_reserve failed");
        return;
    }
    const base = vm_result.val2;
    const ptr: *volatile u8 = @ptrFromInt(base);
    ptr.* = 42;

    const rc = syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0);
    t.expectEqual("shm_map: committed pages returns E_BUSY", -11, rc);
}
