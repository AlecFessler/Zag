const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn spinThread() void {
    // Busy-spin so the thread stays in .running state.
    while (true) {}
}

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, handle: u64) ?*const perm_view.UserViewEntry {
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            return &view[i];
        }
    }
    return null;
}

/// §2.4.9 — `thread_suspend` on a `.running` thread causes it to enter `.suspended` state; if running on a remote core, a scheduling IPI is issued to force the transition at the next scheduling point
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const ret = syscall.thread_create(&spinThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.4.9 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Yield a few times to let the thread start running.
    for (0..10) |_| {
        syscall.thread_yield();
    }

    // Suspend the running thread.
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret < 0) {
        t.failWithVal("§2.4.9 thread_suspend failed", 0, suspend_ret);
        syscall.shutdown();
    }

    // Yield to allow the kernel to process the suspension (IPI + scheduling point).
    for (0..10) |_| {
        syscall.thread_yield();
    }

    // Verify the thread is now in suspended state (4).
    if (findThreadEntry(view, handle)) |entry| {
        const state = entry.threadState();
        if (state == 4) {
            t.pass("§2.4.9");
        } else {
            t.failWithVal("§2.4.9 expected suspended(4)", 4, @as(i64, state));
        }
    } else {
        t.fail("§2.4.9 thread entry not found");
    }

    syscall.shutdown();
}
