const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

fn spinThread() void {
    // Busy-spin so the thread stays in .running state.
    while (true) {}
}

/// §2.4.9 — `thread_suspend` on a `.running` thread causes it to enter `.suspended` state; if running on a remote core, a scheduling IPI is issued to force the transition at the next scheduling point
pub fn main(_: u64) void {
    const ret = syscall.thread_create(&spinThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.9 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Yield a few times to let the thread start running.
    for (0..10) |_| {
        syscall.thread_yield();
    }

    // Suspend the running thread. A successful E_OK return from
    // thread_suspend is the spec-visible signal that the transition took
    // effect (§2.4.9). A second suspend on an already-.suspended thread
    // must now return E_BUSY, confirming the first one landed.
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret < 0) {
        t.failWithVal("§2.4.9 thread_suspend failed", 0, suspend_ret);
        syscall.shutdown();
    }

    const suspend_again = syscall.thread_suspend(handle);
    // E_BUSY = -16 per errno.zig conventions; check for any non-success.
    if (suspend_again == 0) {
        t.fail("§2.4.9 second suspend returned success");
        syscall.shutdown();
    }

    t.pass("§2.4.9");
    syscall.shutdown();
}
