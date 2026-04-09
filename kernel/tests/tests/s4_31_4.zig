const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

fn loopForever() void {
    while (true) {
        asm volatile ("pause");
    }
}

/// §4.31.4 — `thread_resume` on a thread not in `.suspended` state returns `E_INVAL`
pub fn main(_: u64) void {
    // Create a thread that is running (not suspended).
    const ret = syscall.thread_create(&loopForever, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§4.31.4 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let it start running.
    for (0..5) |_| syscall.thread_yield();

    // Resuming a running thread should return E_INVAL.
    const resume_ret = syscall.thread_resume(handle);
    t.expectEqual("§4.31.4", E_INVAL, resume_ret);

    // Clean up.
    _ = syscall.thread_kill(handle);
    syscall.shutdown();
}
