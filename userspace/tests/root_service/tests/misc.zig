const lib = @import("lib");
const syscall = lib.syscall;
const t = lib.testing;
const perms = lib.perms;

pub fn run() void {
    t.section("disable_restart + revoke_perm");
    testRevokeInvalidHandle();
    testRevokeSelf();
    testRevokeVmReservation();
    testDisableRestart();
}

fn testClockGettime() void {
    const t1 = syscall.clock_gettime();
    const t2 = syscall.clock_gettime();
    if (t2 >= t1 and t1 > 0) {
        t.pass("clock_gettime: monotonic and nonzero");
    } else {
        t.fail("clock_gettime: not monotonic or zero");
    }
}

fn testDisableRestart() void {
    const rc = syscall.disable_restart();
    t.expectEqual("disable_restart: succeeds (root has restart)", 0, rc);

    const rc2 = syscall.disable_restart();
    t.expectEqual("disable_restart: second call returns E_PERM", -2, rc2);
}

fn testRevokeInvalidHandle() void {
    const rc = syscall.revoke_perm(99999);
    t.expectEqual("revoke_perm: invalid handle returns E_BADCAP", -3, rc);
}

fn testRevokeSelf() void {
    const rc = syscall.revoke_perm(0);
    t.expectEqual("revoke_perm: HANDLE_SELF rejected", -1, rc);
}

fn testRevokeVmReservation() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("revoke_vm: reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;

    const ptr: *volatile u8 = @ptrFromInt(base);
    ptr.* = 77;

    const rc = syscall.revoke_perm(handle);
    t.expectEqual("revoke_vm: revoke succeeds", 0, rc);

    const rc2 = syscall.revoke_perm(handle);
    t.expectEqual("revoke_vm: double revoke returns E_BADCAP", -3, rc2);
}
