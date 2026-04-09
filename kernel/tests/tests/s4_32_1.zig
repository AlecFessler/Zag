const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

fn loopForever() void {
    while (true) {
        asm volatile ("pause");
    }
}

/// §4.32.1 — `thread_kill` returns `E_OK` on success
pub fn main(_: u64) void {
    const ret = syscall.thread_create(&loopForever, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§4.32.1 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let it start running.
    for (0..5) |_| syscall.thread_yield();

    const kill_ret = syscall.thread_kill(handle);
    t.expectEqual("§4.32.1", E_OK, kill_ret);

    syscall.shutdown();
}
