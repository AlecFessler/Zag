const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("revoke_perm + disable_restart + clock (S2.4, S2.11, S4)");
    testClockGettime();
    testRevokeInvalidHandle();
    testRevokeSelf();
    testRevokeVmReservation();
    testDisableRestartAlreadyCleared();
}

fn testClockGettime() void {
    const t1 = syscall.clock_gettime();
    const t2 = syscall.clock_gettime();
    if (t2 >= t1 and t1 > 0) {
        t.pass("S4.clock_gettime: monotonic and nonzero");
    } else {
        t.fail("S4.clock_gettime: not monotonic or zero");
    }
}

fn testDisableRestartAlreadyCleared() void {
    const rc = syscall.disable_restart();
    t.expectEqual("S4.disable_restart: already cleared returns E_PERM", -2, rc);
}

fn testRevokeInvalidHandle() void {
    const rc = syscall.revoke_perm(99999);
    t.expectEqual("S4.revoke_perm: nonexistent handle returns E_BADCAP", -3, rc);
}

fn testRevokeSelf() void {
    const rc = syscall.revoke_perm(0);
    t.expectEqual("S4.revoke_perm: cannot revoke HANDLE_SELF (E_INVAL)", -1, rc);
}

fn testRevokeVmReservation() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) { t.fail("setup failed"); return; }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;
    const ptr: *volatile u8 = @ptrFromInt(base);
    ptr.* = 77;
    const rc = syscall.revoke_perm(handle);
    t.expectEqual("S2.4.revoke(vm_reservation): frees pages, removes nodes", 0, rc);
    const rc2 = syscall.revoke_perm(handle);
    t.expectEqual("S2.4: revoked slot cleared, double revoke E_BADCAP", -3, rc2);
}
