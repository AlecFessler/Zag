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

/// §2.2.48 — `thread_suspend` returns `E_OK` on success.
///
/// Observe the side effect: after suspend, a worker thread no longer advances
/// the shared counter.
pub fn main(_: u64) void {
    const thread_handle = syscall.thread_create(&counterLoop, 0, 4);
    if (thread_handle <= 0) {
        t.failWithVal("§2.2.48 thread_create", 1, thread_handle);
        syscall.shutdown();
    }

    // Let the worker get going.
    while (@atomicLoad(u64, &counter, .seq_cst) < 5) syscall.thread_yield();

    const ret = syscall.thread_suspend(@bitCast(thread_handle));
    t.expectEqual("§2.2.48 suspend rc", E_OK, ret);

    // Capture the counter, yield many times, verify no forward progress.
    const snapshot = @atomicLoad(u64, &counter, .seq_cst);
    for (0..200) |_| syscall.thread_yield();
    const after = @atomicLoad(u64, &counter, .seq_cst);
    if (after == snapshot) {
        t.pass("§2.2.48 worker halted after suspend");
    } else {
        t.failWithVal("§2.2.48 worker still running", @intCast(snapshot), @intCast(after));
    }
    syscall.shutdown();
}
