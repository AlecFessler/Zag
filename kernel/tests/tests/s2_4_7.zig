const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn spinThread() void {
    // Spin until suspended or killed.
    while (true) {
        syscall.thread_yield();
    }
}

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, handle: u64) ?*const perm_view.UserViewEntry {
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            return &view[i];
        }
    }
    return null;
}

/// §2.4.7 — The user permissions view `field0` for a thread entry is updated on every thread state transition
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&spinThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.7 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // After creation, thread should be ready (0) or running (1).
    var passed_initial = false;
    if (findThreadEntry(view, handle)) |entry| {
        const state = entry.threadState();
        if (state == 0 or state == 1) {
            passed_initial = true;
        }
    }

    if (!passed_initial) {
        t.fail("§2.4.7 initial state not ready/running");
        syscall.shutdown();
    }

    // Suspend the thread — state should become 4 (suspended).
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret < 0) {
        t.fail("§2.4.7 thread_suspend failed");
        syscall.shutdown();
    }

    // Yield to let the kernel process the suspension.
    syscall.thread_yield();

    var passed_suspended = false;
    if (findThreadEntry(view, handle)) |entry| {
        const state = entry.threadState();
        if (state == 4) {
            passed_suspended = true;
        }
    }

    if (!passed_suspended) {
        t.fail("§2.4.7 state not updated to suspended");
        syscall.shutdown();
    }

    // Resume the thread — state should go back to ready (0) or running (1).
    const resume_ret = syscall.thread_resume(handle);
    if (resume_ret < 0) {
        t.fail("§2.4.7 thread_resume failed");
        syscall.shutdown();
    }

    syscall.thread_yield();

    var passed_resumed = false;
    if (findThreadEntry(view, handle)) |entry| {
        const state = entry.threadState();
        if (state == 0 or state == 1) {
            passed_resumed = true;
        }
    }

    if (!passed_resumed) {
        t.fail("§2.4.7 state not updated after resume");
        syscall.shutdown();
    }

    t.pass("§2.4.7");
    syscall.shutdown();
}
