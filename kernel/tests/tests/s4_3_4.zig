const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.3.4 — `vm_reserve` with zero hint finds a free range.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const r1 = syscall.vm_reserve(0, 4096, rw.bits());
    const r2 = syscall.vm_reserve(0, 4096, rw.bits());
    if (r1.val <= 0 or r2.val <= 0 or r1.val2 == 0 or r2.val2 == 0) {
        t.fail("§4.3.4");
        syscall.shutdown();
    }

    // Two zero-hint reserves should get different addresses, both usable.
    const p1: *volatile u64 = @ptrFromInt(r1.val2);
    const p2: *volatile u64 = @ptrFromInt(r2.val2);
    p1.* = 0xAAAA;
    p2.* = 0xBBBB;
    if (r1.val2 != r2.val2 and p1.* == 0xAAAA and p2.* == 0xBBBB) {
        t.pass("§4.3.4");
    } else {
        t.fail("§4.3.4");
    }
    syscall.shutdown();
}
