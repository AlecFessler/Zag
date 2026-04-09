const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.3.7 — `vm_reserve` with non-page-aligned size returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 100, rw.bits());
    t.expectEqual("§4.3.7", E_INVAL, result.val);
    syscall.shutdown();
}
