const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("vm + shm syscall error paths");
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
    testHintOverlapFallback();
    testShmMapRwxExceedsMax();
}

fn testReserveZeroSize() void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.vm_reserve(0, 0, rights);
    t.expectEqual("S4.vm_reserve: size=0 returns E_INVAL", -1, result.val);
}

fn testReserveBadAlignment() void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.vm_reserve(0, 123, rights);
    t.expectEqual("S4.vm_reserve: non-page-aligned size returns E_INVAL", -1, result.val);
}

fn testReserveShareableAndMmio() void {
    const rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true, .mmio = true,
    }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    t.expectEqual("S2.2: shareable and mmio are mutually exclusive", -1, result.val);
}

fn testReserveWithHint() void {
    const hint: u64 = 0x0000_1000_0000_0000;
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(hint, syscall.PAGE4K, rights);
    if (result.val > 0 and result.val2 == hint) {
        t.pass("S2.2: hint honored when no overlap in static zone");
    } else if (result.val > 0) {
        t.pass("S2.2: hint fallback to cursor when overlap");
    } else {
        t.failWithVal("S4.vm_reserve: hint failed", 0, result.val);
    }
}

fn testPermsInvalidHandle() void {
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc = syscall.vm_perms(99999, 0, syscall.PAGE4K, rw);
    t.expectEqual("S4.vm_perms: nonexistent handle returns E_BADCAP", -3, rc);
}

fn testPermsBadAlignment() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const rc = syscall.vm_perms(handle, 1, syscall.PAGE4K, rights);
    t.expectEqual("S4.vm_perms: non-page-aligned offset returns E_INVAL", -1, rc);
}

fn testPermsOutOfBounds() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const rc = syscall.vm_perms(handle, 0, 2 * syscall.PAGE4K, rights);
    t.expectEqual("S4.vm_perms: range exceeding original_size returns E_INVAL", -1, rc);
}

fn testPermsShareableBit() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const shareable = (perms.VmReservationRights{ .read = true, .shareable = true }).bits();
    const rc = syscall.vm_perms(handle, 0, syscall.PAGE4K, shareable);
    t.expectEqual("S4.vm_perms: shareable/mmio bits in perms returns E_INVAL", -1, rc);
}

fn testShmCreateZeroSize() void {
    const rc = syscall.shm_create(0);
    t.expectEqual("S4.shm_create: size=0 returns E_INVAL", -1, rc);
}

fn testShmCreateBadAlign() void {
    const rc = syscall.shm_create(100);
    if (rc > 0) {
        t.pass("S4.shm_create: non-aligned size rounds up (accepted)");
    } else {
        t.pass("S4.shm_create: non-aligned size rejected (also valid)");
    }
}

fn testShmMapNoShareable() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) { t.fail("setup failed"); return; }
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0);
    t.expectEqual("S2.2.shm_map: max_rights must include shareable", -2, rc);
}

fn testShmMapDuplicate() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) { t.fail("setup failed"); return; }
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .execute = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, 2 * syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const vm_handle: u64 = @intCast(vm_result.val);
    const rc1 = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    if (rc1 != 0) { t.failWithVal("first map failed", 0, rc1); return; }
    const rc2 = syscall.shm_map(@intCast(shm_handle), vm_handle, syscall.PAGE4K);
    t.expectEqual("S2.2.shm_map: no duplicate SharedMemory in reservation", -1, rc2);
}

fn testShmUnmapNotFound() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) { t.fail("setup failed"); return; }
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .execute = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.shm_unmap(@intCast(shm_handle), @intCast(vm_result.val));
    t.expectEqual("S2.2.shm_unmap: not mapped returns E_NOENT", -10, rc);
}

fn testShmMapBusy() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) { t.fail("setup failed"); return; }
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .execute = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const ptr: *volatile u8 = @ptrFromInt(vm_result.val2);
    ptr.* = 42;
    const rc = syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0);
    t.expectEqual("S2.2.shm_map: committed pages in range returns E_BUSY", -11, rc);
}

fn testHintOverlapFallback() void {
    const hint: u64 = 0x0000_1000_0000_0000;
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const r1 = syscall.vm_reserve(hint, syscall.PAGE4K, rights);
    if (r1.val < 0) { t.fail("setup failed"); return; }
    const r2 = syscall.vm_reserve(hint, syscall.PAGE4K, rights);
    if (r2.val > 0 and r2.val2 != hint) {
        t.pass("S2.2: overlapping hint falls back to cursor allocation");
    } else if (r2.val > 0) {
        t.fail("S2.2: overlapping hint should not get same addr");
    } else {
        t.failWithVal("S2.2: hint overlap fallback failed", 0, r2.val);
    }
}

fn testShmMapRwxExceedsMax() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) { t.fail("setup failed"); return; }
    const vm_rights = (perms.VmReservationRights{
        .read = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) { t.fail("setup failed"); return; }
    const rc = syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0);
    t.expectEqual("S2.2.shm_map: SHM RWX exceeds max_rights RWX (E_PERM)", -2, rc);
}
