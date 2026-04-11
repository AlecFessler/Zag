const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.3.8 — `mem_reserve` with `shareable` + `mmio` both set returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const bad = perms.VmReservationRights{ .read = true, .write = true, .shareable = true, .mmio = true };
    const result = syscall.mem_reserve(0, 4096, bad.bits());
    t.expectEqual("§4.3.8", E_INVAL, result.val);
    syscall.shutdown();
}
