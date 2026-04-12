const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.20 — `mem_perms` with invalid handle returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true };
    const ret = syscall.mem_perms(99999, 0, 4096, rw.bits());
    t.expectEqual("§2.3.20", E_BADHANDLE, ret);
    syscall.shutdown();
}
