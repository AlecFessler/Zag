const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.18 — `notify_wait` atomically reads and clears the notification word.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // With no pending notifications, notify_wait(0) returns E_AGAIN.
    // Call it twice to confirm idempotent behavior (the word is already
    // zero, so both calls should return E_AGAIN).
    const rc1 = syscall.notify_wait(0);
    const rc2 = syscall.notify_wait(0);
    if (rc1 == syscall.E_AGAIN and rc2 == syscall.E_AGAIN) {
        t.pass("§2.5.18");
    } else {
        t.fail("§2.5.18");
    }
    syscall.shutdown();
}
