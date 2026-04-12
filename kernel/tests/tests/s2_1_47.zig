const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.47 — Handles are monotonically increasing u64 IDs, unique per process lifetime.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const r1 = syscall.mem_reserve(0, 4096, rw.bits());
    const r2 = syscall.mem_reserve(0, 4096, rw.bits());
    const r3 = syscall.mem_reserve(0, 4096, rw.bits());
    const h1: u64 = @bitCast(r1.val);
    const h2: u64 = @bitCast(r2.val);
    const h3: u64 = @bitCast(r3.val);
    if (h2 > h1 and h3 > h2) {
        t.pass("§2.1.47");
    } else {
        t.fail("§2.1.47");
    }
    syscall.shutdown();
}
