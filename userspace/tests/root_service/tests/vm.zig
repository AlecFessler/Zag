const lib = @import("lib");
const syscall = lib.syscall;
const t = lib.testing;
const perms = lib.perms;

pub fn run() void {
    t.section("vm_reserve + vm_perms");
    testReserveBasic();
    testPermsChange();
    testPermsExceedMax();
    testMergeSplitRestore();
    testDecommit();
}

fn testReserveBasic() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4 * syscall.PAGE4K, rights);
    t.expectOk("reserve returns handle", result.val);
}

fn testPermsChange() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4 * syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("perms_change: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);

    const ro = (perms.VmReservationRights{ .read = true }).bits();
    const rc = syscall.vm_perms(handle, syscall.PAGE4K, 2 * syscall.PAGE4K, ro);
    t.expectEqual("perms_change: set middle RO", 0, rc);
}

fn testPermsExceedMax() void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("perms_exceed: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);

    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc = syscall.vm_perms(handle, 0, syscall.PAGE4K, rw);
    t.expectEqual("perms_exceed: RW on R-only reservation rejected", -2, rc);
}

fn testMergeSplitRestore() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4 * syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("merge: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;

    const ro = (perms.VmReservationRights{ .read = true }).bits();
    const rc1 = syscall.vm_perms(handle, syscall.PAGE4K, 2 * syscall.PAGE4K, ro);

    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc2 = syscall.vm_perms(handle, syscall.PAGE4K, 2 * syscall.PAGE4K, rw);

    if (rc1 != 0) {
        t.failWithVal("merge: split vm_perms failed", 0, rc1);
        return;
    }
    if (rc2 != 0) {
        t.failWithVal("merge: restore vm_perms failed", 0, rc2);
        return;
    }

    const p0: *volatile u8 = @ptrFromInt(base);
    p0.* = 42;
    const p1: *volatile u8 = @ptrFromInt(base + syscall.PAGE4K);
    p1.* = 43;
    const p2: *volatile u8 = @ptrFromInt(base + 2 * syscall.PAGE4K);
    p2.* = 44;
    const p3: *volatile u8 = @ptrFromInt(base + 3 * syscall.PAGE4K - 1);
    p3.* = 45;

    if (p0.* == 42 and p1.* == 43 and p2.* == 44 and p3.* == 45) {
        t.pass("merge: split-restore-access all pages");
    } else {
        t.fail("merge: data verification failed");
    }
}

fn testDecommit() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("decommit: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;

    const ptr: *volatile u64 = @ptrFromInt(base);
    ptr.* = 0xCAFEBABE;
    if (ptr.* != 0xCAFEBABE) {
        t.fail("decommit: initial write failed");
        return;
    }

    const zero = (perms.VmReservationRights{}).bits();
    const rc1 = syscall.vm_perms(handle, 0, syscall.PAGE4K, zero);
    if (rc1 != 0) {
        t.failWithVal("decommit: vm_perms(0) failed", 0, rc1);
        return;
    }

    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc2 = syscall.vm_perms(handle, 0, syscall.PAGE4K, rw);
    if (rc2 != 0) {
        t.failWithVal("decommit: vm_perms(RW) restore failed", 0, rc2);
        return;
    }

    if (ptr.* == 0) {
        t.pass("decommit: page zeroed after decommit+recommit");
    } else {
        t.fail("decommit: page not zeroed after decommit+recommit");
    }
}
