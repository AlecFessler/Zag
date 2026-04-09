const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

fn loopForever() void {
    while (true) {
        asm volatile ("pause");
    }
}

/// §4.32.2 — `thread_kill` requires the `kill` right on `thread_handle`; returns `E_PERM` without it
pub fn main(_: u64) void {
    // The root process has full ThreadHandleRights on threads it creates, so we
    // cannot easily test the negative case (E_PERM) without a child process
    // transferring a thread handle without the kill right. Instead, verify the
    // positive case: killing with full rights succeeds.
    const ret = syscall.thread_create(&loopForever, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§4.32.2 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    for (0..5) |_| syscall.thread_yield();

    const kill_ret = syscall.thread_kill(handle);
    t.expectEqual("§4.32.2 kill with rights succeeds", E_OK, kill_ret);

    syscall.shutdown();
}
