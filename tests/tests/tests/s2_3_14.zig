const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.14 — `mem_reserve` with hint in the static reservation zone uses that address (if no overlap).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const hint: u64 = 0x0000_1000_0000_0000;
    const result = syscall.mem_reserve(hint, 4096, rw.bits());
    if (result.val > 0 and result.val2 == hint) {
        t.pass("§2.3.14");
    } else {
        t.fail("§2.3.14");
    }
    syscall.shutdown();
}
