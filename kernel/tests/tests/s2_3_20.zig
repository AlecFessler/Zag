const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var counter: u64 align(8) = 0;

fn incrementer() void {
    while (true) {
        _ = @atomicRmw(u64, &counter, .Add, 1, .acq_rel);
        _ = syscall.futex_wake(@ptrCast(&counter), 1);
        syscall.thread_yield();
    }
}

/// §2.3.20 — Revoking a thread handle removes it from the permissions table without affecting the thread's execution or state
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create a thread and get its handle.
    const handle_ret = syscall.thread_create(&incrementer, 0, 4);
    if (handle_ret <= 0) {
        t.failWithVal("§2.3.20 thread_create", 1, handle_ret);
        syscall.shutdown();
    }
    const thread_handle: u64 = @bitCast(handle_ret);

    // Wait for the thread to start incrementing.
    t.waitUntilNonZero(&counter);

    // Verify the thread handle exists in the perm view.
    var found_before = false;
    for (0..128) |i| {
        if (view[i].handle == thread_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            found_before = true;
            break;
        }
    }
    if (!found_before) {
        t.fail("§2.3.20 handle not found before revoke");
        syscall.shutdown();
    }

    // Record counter value before revoke.
    const before = @atomicLoad(u64, &counter, .acquire);

    // Revoke the thread handle.
    const revoke_ret = syscall.revoke_perm(thread_handle);
    if (revoke_ret != 0) {
        t.failWithVal("§2.3.20 revoke_perm", 0, revoke_ret);
        syscall.shutdown();
    }

    // Verify handle is removed from perm view.
    var found_after = false;
    for (0..128) |i| {
        if (view[i].handle == thread_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            found_after = true;
            break;
        }
    }
    if (found_after) {
        t.fail("§2.3.20 handle still present after revoke");
        syscall.shutdown();
    }

    // Verify the thread is still running by checking counter increments.
    for (0..10) |_| syscall.thread_yield();
    const after = @atomicLoad(u64, &counter, .acquire);

    if (after > before) {
        t.pass("§2.3.20");
    } else {
        t.fail("§2.3.20 thread stopped after revoke");
    }
    syscall.shutdown();
}
