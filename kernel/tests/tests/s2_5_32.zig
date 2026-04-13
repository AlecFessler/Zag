const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.32 — The removed `notify_wait` syscall returns `E_INVAL` instead of timing out.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rc = syscall.notify_wait(1_000_000);
    t.expectEqual("§2.5.32", syscall.E_INVAL, rc);
    syscall.shutdown();
}
