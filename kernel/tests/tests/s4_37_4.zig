const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

fn loopForever() void {
    while (true) {
        asm volatile ("pause");
    }
}

/// §4.37.4 — `fault_set_thread_mode` with invalid `mode` value returns `E_INVAL`
pub fn main(_: u64) void {
    // Create a thread to have a valid thread handle.
    const ret = syscall.thread_create(&loopForever, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§4.37.4 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    for (0..5) |_| syscall.thread_yield();

    // Set mode to an invalid value (99).
    const mode_ret = syscall.fault_set_thread_mode(handle, 99);
    t.expectEqual("§4.37.4", E_INVAL, mode_ret);

    _ = syscall.thread_kill(handle);
    syscall.shutdown();
}
