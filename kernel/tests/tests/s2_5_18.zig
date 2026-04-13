const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.18 — The removed `notify_wait` syscall returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // notify_wait was removed; both calls should return E_INVAL.
    const rc1 = syscall.notify_wait(0);
    const rc2 = syscall.notify_wait(1_000_000);
    if (rc1 == syscall.E_INVAL and rc2 == syscall.E_INVAL) {
        t.pass("§2.5.18");
    } else {
        t.fail("§2.5.18");
    }
    syscall.shutdown();
}
