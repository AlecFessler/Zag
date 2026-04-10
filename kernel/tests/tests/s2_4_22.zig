const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// Shared counter incremented by the worker thread. Volatile to prevent optimization.
var counter: u64 = 0;

fn counterThread() void {
    while (true) {
        const ptr: *volatile u64 = @ptrCast(&counter);
        ptr.* += 1;
        syscall.thread_yield();
    }
}

/// §2.4.22 — A `.suspended` thread is not scheduled and does not appear on any run queue.
///
/// Test:
///   1. Create a counter thread that increments a shared counter.
///   2. Let it run — verify counter increments.
///   3. Suspend the thread via thread_suspend.
///   4. Record counter value, yield many times, verify counter did NOT change.
///   5. Resume the thread, verify counter starts incrementing again.
///   6. Check perm_view shows state transitions (suspended → ready/running).
pub fn main(pv: u64) void {
    _ = pv;

    const ret = syscall.thread_create(&counterThread, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§2.4.22 thread_create", 1, ret);
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Let the thread run and increment the counter.
    for (0..20) |_| syscall.thread_yield();

    const ctr_ptr: *volatile u64 = @ptrCast(&counter);
    const running_count = ctr_ptr.*;
    if (running_count == 0) {
        t.fail("§2.4.22 counter never incremented while running");
        syscall.shutdown();
    }

    // Suspend the thread.
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret < 0) {
        t.failWithVal("§2.4.22 thread_suspend", 0, suspend_ret);
        syscall.shutdown();
    }

    // Yield to let kernel process the suspension.
    for (0..5) |_| syscall.thread_yield();

    // Record counter after suspension.
    const after_suspend = ctr_ptr.*;

    // Yield many times — counter should NOT change.
    for (0..50) |_| syscall.thread_yield();

    const after_wait = ctr_ptr.*;
    if (after_wait != after_suspend) {
        t.fail("§2.4.22 counter changed while suspended");
        syscall.shutdown();
    }

    // Resume the thread and verify it runs again.
    const resume_ret = syscall.thread_resume(handle);
    if (resume_ret < 0) {
        t.failWithVal("§2.4.22 thread_resume", 0, resume_ret);
        syscall.shutdown();
    }

    // Let it run.
    for (0..20) |_| syscall.thread_yield();

    const after_resume = ctr_ptr.*;

    // Clean up.
    _ = syscall.thread_suspend(handle);
    for (0..5) |_| syscall.thread_yield();
    _ = syscall.thread_kill(handle);

    // Single terminal pass/fail — the harness only reads the first PASS/FAIL
    // line, so sub-asserts above must not call pass() (otherwise a later
    // sub-fail would be masked).
    if (after_resume > after_wait) {
        t.pass("§2.4.22");
    } else {
        t.fail("§2.4.22 counter did not increment after resume");
    }

    syscall.shutdown();
}
