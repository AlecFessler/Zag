const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.3.29 — `mem_perms` with perms exceeding `max_rights` returns `E_PERM`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Create reservation with read-only max rights.
    const ro = perms.VmReservationRights{ .read = true };
    const result = syscall.mem_reserve(0, 4096, ro.bits());
    const handle: u64 = @bitCast(result.val);
    // Try to set write permission, which exceeds max_rights.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const ret = syscall.mem_perms(handle, 0, 4096, rw.bits());
    t.expectEqual("§2.3.29", E_PERM, ret);
    syscall.shutdown();
}
