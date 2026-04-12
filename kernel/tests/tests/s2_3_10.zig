const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.10 — `mem_reserve` returns handle ID (positive) on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    if (result.val > 0) {
        t.pass("§2.3.10");
    } else {
        t.failWithVal("§2.3.10", 1, result.val);
    }
    syscall.shutdown();
}
