const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var done: u64 align(8) = 0;
var after_exit: u64 align(8) = 0;

fn child() void {
    @atomicStore(u64, &done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done), 1);
    syscall.thread_exit();
    // If thread_exit returns, this code runs — which should never happen.
    @atomicStore(u64, &after_exit, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&after_exit), 1);
}

/// §4.12.1 — `thread_exit` terminates the calling thread (does not return).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&child, 0, 4);
    t.waitUntilNonZero(&done);
    // Give time for any post-exit code to run (it shouldn't).
    for (0..100) |_| syscall.thread_yield();
    // Verify thread_exit did not return — after_exit must still be 0.
    if (@atomicLoad(u64, &after_exit, .acquire) == 0) {
        t.pass("§4.12.1");
    } else {
        t.fail("§4.12.1");
    }
    syscall.shutdown();
}
