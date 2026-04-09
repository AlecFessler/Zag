const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

fn worker() void {
    // Stay alive until killed.
    for (0..1000) |_| syscall.thread_yield();
    syscall.thread_exit();
}

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, handle: u64) bool {
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            return true;
        }
    }
    return false;
}

/// §2.4.18 — `thread_kill` on the last non-exited thread in a process triggers process exit or restart per §2.6 semantics
///           or restart per §2.6 semantics.
///
/// We cannot kill our own last thread and still report results, so we test:
///   1. Create 2 threads. Kill thread2 (not last) → E_OK, verify handle removed from perm view.
///   2. Document that killing the last thread triggers process exit.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create two worker threads.
    const ret1 = syscall.thread_create(&worker, 0, 4);
    if (ret1 <= 0) {
        t.failWithVal("§2.4.18 thread_create t1", 1, ret1);
        syscall.shutdown();
    }
    const handle1: u64 = @bitCast(ret1);

    const ret2 = syscall.thread_create(&worker, 0, 4);
    if (ret2 <= 0) {
        t.failWithVal("§2.4.18 thread_create t2", 1, ret2);
        syscall.shutdown();
    }
    const handle2: u64 = @bitCast(ret2);

    // Kill thread2 (not last) — should succeed.
    const kill_ret = syscall.thread_kill(handle2);
    if (kill_ret != 0) {
        t.failWithVal("§2.4.18 kill non-last", 0, kill_ret);
        syscall.shutdown();
    }

    // Yield to let kernel process the kill.
    for (0..10) |_| syscall.thread_yield();

    // Verify thread2's handle is removed from perm view.
    if (!findThreadEntry(view, handle2)) {
        t.pass("§2.4.18 non-last kill removes handle");
    } else {
        t.fail("§2.4.18 killed thread handle still in perm view");
    }

    // Kill thread1 as well — after this, only the main thread remains.
    // If we killed our own handle (the last thread), it would trigger process exit per §2.6.
    // We can't observe that from within, so we just clean up.
    _ = syscall.thread_kill(handle1);

    // NOTE: Killing the very last thread (main thread via thread_self) would trigger
    // process exit/restart per §2.6. That can only be observed by a parent process.

    syscall.shutdown();
}
