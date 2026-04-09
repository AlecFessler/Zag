const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;
const E_BUSY: i64 = -11;

fn loopForever() void {
    while (true) {
        syscall.thread_yield();
    }
}

/// §4.30.5 — `thread_suspend` on a thread already in `.suspended` state returns `E_BUSY`.
pub fn main(_: u64) void {
    const thread_handle = syscall.thread_create(&loopForever, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§4.30.5 thread_create", 1, thread_handle);
        syscall.shutdown();
    }

    // Let thread start running.
    for (0..5) |_| syscall.thread_yield();

    // First suspend should succeed.
    const ret1 = syscall.thread_suspend(@bitCast(thread_handle));
    if (ret1 != E_OK) {
        t.failWithVal("§4.30.5 first suspend", E_OK, ret1);
        syscall.shutdown();
    }

    // Second suspend on already-suspended thread should return E_BUSY.
    const ret2 = syscall.thread_suspend(@bitCast(thread_handle));
    t.expectEqual("§4.30.5", E_BUSY, ret2);
    syscall.shutdown();
}
