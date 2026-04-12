const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.16 — `mem_reserve` with non-page-aligned size returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 100, rw.bits());
    t.expectEqual("§2.3.16", E_INVAL, result.val);
    syscall.shutdown();
}
