const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.4.2 — `vm_perms` with invalid handle returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true };
    const ret = syscall.vm_perms(99999, 0, 4096, rw.bits());
    t.expectEqual("§4.4.2", E_BADHANDLE, ret);
    syscall.shutdown();
}
