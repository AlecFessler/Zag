const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

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
    t.expectOk("S4.vm_reserve: returns positive handle for RW region", result.val);
}

fn testPermsChange() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4 * syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const ro = (perms.VmReservationRights{ .read = true }).bits();
    const rc = syscall.vm_perms(handle, syscall.PAGE4K, 2 * syscall.PAGE4K, ro);
    t.expectEqual("S2.3.vm_perms: set current_rights on sub-range", 0, rc);
}

fn testPermsExceedMax() void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc = syscall.vm_perms(handle, 0, syscall.PAGE4K, rw);
    t.expectEqual("S2.3: new_rights must be <= max_rights RWX", -2, rc);
}

fn testMergeSplitRestore() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4 * syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;
    const ro = (perms.VmReservationRights{ .read = true }).bits();
    const rc1 = syscall.vm_perms(handle, syscall.PAGE4K, 2 * syscall.PAGE4K, ro);
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc2 = syscall.vm_perms(handle, syscall.PAGE4K, 2 * syscall.PAGE4K, rw);
    if (rc1 != 0 or rc2 != 0) { t.fail("S2.3: split/merge perms call failed"); return; }
    const p0: *volatile u8 = @ptrFromInt(base);
    p0.* = 42;
    const p1: *volatile u8 = @ptrFromInt(base + syscall.PAGE4K);
    p1.* = 43;
    const p2: *volatile u8 = @ptrFromInt(base + 2 * syscall.PAGE4K);
    p2.* = 44;
    const p3: *volatile u8 = @ptrFromInt(base + 3 * syscall.PAGE4K - 1);
    p3.* = 45;
    if (p0.* == 42 and p1.* == 43 and p2.* == 44 and p3.* == 45) {
        t.pass("S2.3: split then merge restores access to all pages");
    } else {
        t.fail("S2.3: split/merge data verification failed");
    }
}

fn testDecommit() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;
    const ptr: *volatile u64 = @ptrFromInt(base);
    ptr.* = 0xCAFEBABE;
    const zero = (perms.VmReservationRights{}).bits();
    const rc1 = syscall.vm_perms(handle, 0, syscall.PAGE4K, zero);
    if (rc1 != 0) { t.fail("S2.3: decommit perms(0) failed"); return; }
    const rw = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const rc2 = syscall.vm_perms(handle, 0, syscall.PAGE4K, rw);
    if (rc2 != 0) { t.fail("S2.3: recommit perms(RW) failed"); return; }
    if (ptr.* == 0) {
        t.pass("S2.3: RWX=0 decommits; recommit demand-pages zeroed page");
    } else {
        t.fail("S2.3: page not zeroed after decommit+recommit");
    }
}
