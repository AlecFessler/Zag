const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.19 — `notify_wait` with `timeout_ns = 0` is non-blocking: returns `E_AGAIN` if the notification word is zero.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rc = syscall.notify_wait(0);
    t.expectEqual("§2.5.19", syscall.E_AGAIN, rc);
    syscall.shutdown();
}
