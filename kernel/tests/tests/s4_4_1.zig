const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.4.1 — `vm_perms` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const read_only = perms.VmReservationRights{ .read = true };
    const ret = syscall.vm_perms(handle, 0, 4096, read_only.bits());
    t.expectEqual("§4.4.1", 0, ret);
    syscall.shutdown();
}
