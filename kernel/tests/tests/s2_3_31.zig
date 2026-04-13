const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.31 — `mem_perms` with RWX = 0 returns `E_INVAL`.
///
/// Duplicate coverage of §2.3.1 — verifies that the zero-rights check applies
/// regardless of prior page state (here we commit a page first).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const ptr: *volatile u64 = @ptrFromInt(result.val2);

    // Commit the page by writing to it.
    ptr.* = 0xDEADBEEF;

    // Setting RWX = 0 must return E_INVAL.
    const zero = perms.VmReservationRights{};
    const ret = syscall.mem_perms(handle, 0, 4096, zero.bits());
    t.expectEqual("§2.3.31", E_INVAL, ret);
    syscall.shutdown();
}
