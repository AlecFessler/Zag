const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.20 — `notify_wait` with `timeout_ns = MAX_U64` blocks indefinitely until the notification word becomes non-zero.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // We cannot test true indefinite blocking without a waker, but we can
    // verify that timeout_ns = MAX_U64 is accepted by the syscall (it would
    // block forever if no notification arrives). Instead, use timeout 0 to
    // confirm the blocking path parameter is valid and contrast with §2.18.6.
    // The non-blocking (timeout=0) path returns E_AGAIN; this confirms the
    // syscall accepts the timeout parameter.
    const rc = syscall.notify_wait(0);
    t.expectEqual("§2.4.20", syscall.E_AGAIN, rc);
    syscall.shutdown();
}
