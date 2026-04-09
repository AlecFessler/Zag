const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.4.3 — `vm_perms` with non-`vm_reservation` handle returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Handle 0 is HANDLE_SELF (a process handle, not vm_reservation).
    const rw = perms.VmReservationRights{ .read = true };
    const ret = syscall.vm_perms(0, 0, 4096, rw.bits());
    t.expectEqual("§4.4.3", E_BADHANDLE, ret);
    syscall.shutdown();
}
