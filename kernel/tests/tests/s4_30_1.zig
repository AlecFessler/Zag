const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

fn loopForever() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §4.30.1 — `thread_suspend` returns `E_OK` on success.
pub fn main(_: u64) void {
    const thread_handle = syscall.thread_create(&loopForever, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§4.30.1 thread_create", 1, thread_handle);
        syscall.shutdown();
    }

    // Yield a few times to let thread start running.
    for (0..5) |_| syscall.thread_yield();

    const ret = syscall.thread_suspend(@bitCast(thread_handle));
    t.expectEqual("§4.30.1", E_OK, ret);
    syscall.shutdown();
}
