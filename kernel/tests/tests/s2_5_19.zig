const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.19 — The removed `notify_wait` syscall returns `E_INVAL` regardless of timeout.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rc = syscall.notify_wait(0);
    t.expectEqual("§2.5.19", syscall.E_INVAL, rc);
    syscall.shutdown();
}
