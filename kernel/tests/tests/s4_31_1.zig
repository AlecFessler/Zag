const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

fn loopForever() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §4.31.1 — `thread_resume` returns `E_OK` on success.
pub fn main(_: u64) void {
    const thread_handle = syscall.thread_create(&loopForever, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§4.31.1 thread_create", 1, thread_handle);
        syscall.shutdown();
    }

    // Let thread start running.
    for (0..5) |_| syscall.thread_yield();

    // Suspend the thread first.
    const suspend_ret = syscall.thread_suspend(@bitCast(thread_handle));
    if (suspend_ret != E_OK) {
        t.failWithVal("§4.31.1 suspend", E_OK, suspend_ret);
        syscall.shutdown();
    }

    // Resume the suspended thread.
    const ret = syscall.thread_resume(@bitCast(thread_handle));
    t.expectEqual("§4.31.1", E_OK, ret);
    syscall.shutdown();
}
