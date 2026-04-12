const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.18.8 — `notify_wait` with a finite timeout returns `E_TIMEOUT` if the notification word remains zero for the duration.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Use a short timeout (1 ms = 1_000_000 ns) so the test doesn't hang.
    const rc = syscall.notify_wait(1_000_000);
    t.expectEqual("§2.18.8", syscall.E_TIMEOUT, rc);
    syscall.shutdown();
}
