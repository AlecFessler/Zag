const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var counter: u64 = 0;

fn counterThread() void {
    while (true) {
        const p: *volatile u64 = @ptrCast(&counter);
        p.* = p.* + 1;
    }
}

/// §2.2.17 — `thread_suspend` on a `.ready` thread removes it from the run queue and enters `.suspended`.
///
/// Thread state is no longer exposed via the perm view, so we verify the
/// behavioral contract: after thread_suspend succeeds, the target no longer
/// runs (it's off the run queue). We create a thread that spins
/// incrementing a shared counter without ever yielding, then suspend it and
/// confirm the counter stops advancing.
pub fn main(_: u64) void {
    const ret = syscall.thread_create(&counterThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.2.17 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let the counter thread actually start running so we're exercising
    // the .ready/.running transition rather than a never-dispatched thread.
    const ctr: *volatile u64 = @ptrCast(&counter);
    while (ctr.* == 0) syscall.thread_yield();

    const suspend_rc = syscall.thread_suspend(handle);
    if (suspend_rc != 0) {
        t.failWithVal("§2.2.17 thread_suspend", 0, suspend_rc);
        syscall.shutdown();
    }

    // Give the kernel time to process the suspension, then snapshot the
    // counter and verify it stops advancing across many yield cycles.
    for (0..10) |_| syscall.thread_yield();
    const after_suspend = ctr.*;
    for (0..50) |_| syscall.thread_yield();
    const after_wait = ctr.*;

    if (after_wait == after_suspend) {
        t.pass("§2.2.17");
    } else {
        t.fail("§2.2.17 counter advanced after suspend");
    }

    _ = syscall.thread_kill(handle);
    syscall.shutdown();
}
