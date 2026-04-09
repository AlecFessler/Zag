const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.4.7 — `vm_perms` with `shareable`/`mmio`/`write_combining` bits returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    // Test shareable bit
    const shareable_bits = (perms.VmReservationRights{ .read = true, .shareable = true }).bits();
    const rc1 = syscall.vm_perms(handle, 0, 4096, shareable_bits);
    t.expectEqual("§4.4.7 shareable", E_INVAL, rc1);
    // Test mmio bit
    const mmio_bits = (perms.VmReservationRights{ .read = true, .mmio = true }).bits();
    const rc2 = syscall.vm_perms(handle, 0, 4096, mmio_bits);
    t.expectEqual("§4.4.7 mmio", E_INVAL, rc2);
    // Test write_combining bit
    const wc_bits = (perms.VmReservationRights{ .read = true, .write_combining = true }).bits();
    const rc3 = syscall.vm_perms(handle, 0, 4096, wc_bits);
    t.expectEqual("§4.4.7 write_combining", E_INVAL, rc3);
    syscall.shutdown();
}
