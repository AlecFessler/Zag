const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.59.5 — `notify_wait` with a finite `timeout_ns` returns `E_TIMEOUT` if the notification word remains zero for the duration.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Use a short timeout (1 ms) to avoid hanging.
    const rc = syscall.notify_wait(1_000_000);
    t.expectEqual("§4.59.5", syscall.E_TIMEOUT, rc);
    syscall.shutdown();
}
