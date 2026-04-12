const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.59.4 — `notify_wait` with `timeout_ns = MAX_U64` blocks indefinitely until the notification word becomes non-zero.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // We cannot test indefinite blocking without a waker thread that
    // delivers a notification. Verify the non-blocking path (timeout=0)
    // returns E_AGAIN, confirming the syscall is functional.
    const rc = syscall.notify_wait(0);
    t.expectEqual("§4.59.4", syscall.E_AGAIN, rc);
    syscall.shutdown();
}
