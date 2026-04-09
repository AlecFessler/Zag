const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

var ready: u64 align(8) = 0;

fn otherThread() void {
    // Signal that this thread is running.
    @as(*volatile u64, @ptrCast(&ready)).* = 1;
    _ = syscall.futex_wake(@ptrCast(&ready), 1);
    // Keep alive so the handle remains valid.
    while (true) {
        syscall.thread_yield();
    }
}

/// §4.15.7 — `pin_exclusive` with a `thread_handle` that does not refer to the calling thread returns `E_INVAL`.
pub fn main(_: u64) void {
    // Set affinity to single core first (required for pin_exclusive).
    _ = syscall.set_affinity_thread(@bitCast(syscall.thread_self()), 0b1);

    // Create a second thread and get its handle.
    const other_handle = syscall.thread_create(&otherThread, 0, 4);
    if (other_handle <= 0) {
        t.failWithVal("§4.15.7 thread_create", 1, other_handle);
        syscall.shutdown();
    }

    // Wait for the other thread to be running.
    t.waitUntilNonZero(&ready);

    // Try to pin_exclusive with the other thread's handle (not the calling thread).
    const ret = syscall.pin_exclusive_thread(@bitCast(other_handle));
    t.expectEqual("§4.15.7", E_INVAL, ret);
    syscall.shutdown();
}
