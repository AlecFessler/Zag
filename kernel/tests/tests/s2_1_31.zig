const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.31 — User address space spans `[0, 0xFFFF_8000_0000_0000)`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    // A vm_reserve with hint=0 should return an address within user space.
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const addr = result.val2;
    // Address should be in [0, 0xFFFF_8000_0000_0000).
    if (result.val > 0 and addr > 0 and addr < 0xFFFF_8000_0000_0000) {
        t.pass("§2.1.31");
    } else {
        t.fail("§2.1.31");
    }
    syscall.shutdown();
}
