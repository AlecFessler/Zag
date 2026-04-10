const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.0.6 — Root service starts with `max_thread_priority` = `pinned`.
///
/// Root should be able to set priority to PINNED (the highest level).
/// This only succeeds if max_thread_priority >= PINNED.
pub fn main(_: u64) void {
    // Pin to a single core first (pinned requires a core to claim).
    _ = syscall.set_affinity(0b1);
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    t.expectOk("§2.0.6 root can pin (max=pinned)", ret);

    // Unpin by setting back to normal.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);

    syscall.shutdown();
}
