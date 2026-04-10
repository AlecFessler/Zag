const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.31 — User address space spans `[0, 0xFFFF_8000_0000_0000)`.
pub fn main(_: u64) void {
    const rw = perms.VmReservationRights{ .read = true, .write = true };

    // A reserve with no hint must land inside user space.
    const ok = syscall.vm_reserve(0, 4096, rw.bits());
    if (ok.val <= 0 or ok.val2 == 0 or ok.val2 >= 0xFFFF_8000_0000_0000) {
        t.fail("§2.1.31 default reservation outside user space");
        syscall.shutdown();
    }
    _ = syscall.revoke_perm(@bitCast(ok.val));

    // A reserve with a hint AT the user-space upper bound must fail: that
    // address belongs to the kernel half and is not a legal user mapping.
    const at_bound = syscall.vm_reserve(0xFFFF_8000_0000_0000, 4096, rw.bits());
    if (at_bound.val > 0) {
        t.fail("§2.1.31 reserve @ 0xFFFF_8000_0000_0000 succeeded");
        _ = syscall.revoke_perm(@bitCast(at_bound.val));
        syscall.shutdown();
    }

    // A reserve with a hint BEYOND the upper bound must also fail.
    const beyond = syscall.vm_reserve(0xFFFF_8000_0000_1000, 4096, rw.bits());
    if (beyond.val > 0) {
        t.fail("§2.1.31 reserve beyond upper bound succeeded");
        _ = syscall.revoke_perm(@bitCast(beyond.val));
        syscall.shutdown();
    }

    t.pass("§2.1.31");
    syscall.shutdown();
}
