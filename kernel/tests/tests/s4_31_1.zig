const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

var counter: u64 align(8) = 0;

fn counterLoop() void {
    while (true) {
        _ = @atomicRmw(u64, &counter, .Add, 1, .seq_cst);
        syscall.thread_yield();
    }
}

/// §4.31.1 — `thread_resume` returns `E_OK` on success.
///
/// Observable behavior: after suspend the counter stalls; after resume it
/// advances again.
pub fn main(_: u64) void {
    const thread_handle = syscall.thread_create(&counterLoop, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§4.31.1 thread_create", 1, thread_handle);
        syscall.shutdown();
    }

    while (@atomicLoad(u64, &counter, .seq_cst) < 5) syscall.thread_yield();

    const suspend_ret = syscall.thread_suspend(@bitCast(thread_handle));
    if (suspend_ret != E_OK) {
        t.failWithVal("§4.31.1 suspend", E_OK, suspend_ret);
        syscall.shutdown();
    }

    // Verify the counter stalled.
    const stalled = @atomicLoad(u64, &counter, .seq_cst);
    for (0..200) |_| syscall.thread_yield();
    if (@atomicLoad(u64, &counter, .seq_cst) != stalled) {
        t.fail("§4.31.1 counter advanced while suspended");
        syscall.shutdown();
    }

    const ret = syscall.thread_resume(@bitCast(thread_handle));
    t.expectEqual("§4.31.1 resume rc", E_OK, ret);

    // Wait for observable forward progress.
    var spins: u64 = 0;
    while (@atomicLoad(u64, &counter, .seq_cst) == stalled) : (spins += 1) {
        if (spins > 100000) {
            t.fail("§4.31.1 counter did not advance after resume");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }
    t.pass("§4.31.1 worker advanced after resume");
    syscall.shutdown();
}
