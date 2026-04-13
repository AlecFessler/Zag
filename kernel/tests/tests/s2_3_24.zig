const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.3.24 — `mem_perms` with non-page-aligned offset returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const ret = syscall.mem_perms(handle, 100, 4096, rw.bits());
    t.expectEqual("§2.3.24", E_INVAL, ret);
    syscall.shutdown();
}
