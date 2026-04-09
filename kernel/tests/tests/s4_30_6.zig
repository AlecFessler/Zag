const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

fn exitImmediately() void {
    syscall.thread_exit();
}

/// §4.30.6 — `thread_suspend` on a thread in `.exited` state returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const thread_handle = syscall.thread_create(&exitImmediately, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§4.30.6 thread_create", 1, thread_handle);
        syscall.shutdown();
    }

    // Yield to let the thread run and exit.
    for (0..10) |_| syscall.thread_yield();

    // Thread has exited; suspend should return E_BADHANDLE.
    const ret = syscall.thread_suspend(@bitCast(thread_handle));
    t.expectEqual("§4.30.6", E_BADHANDLE, ret);
    syscall.shutdown();
}
