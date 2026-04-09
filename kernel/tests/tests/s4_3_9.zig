const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.3.9 — `vm_reserve` with `write_combining` without `mmio` returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const bad = perms.VmReservationRights{ .read = true, .write = true, .write_combining = true };
    const result = syscall.vm_reserve(0, 4096, bad.bits());
    t.expectEqual("§4.3.9", E_INVAL, result.val);
    syscall.shutdown();
}
