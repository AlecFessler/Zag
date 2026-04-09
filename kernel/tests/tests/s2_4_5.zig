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

/// §2.4.5 — Revoking a thread handle via `revoke_perm` removes the handle from the permissions table without killing or suspending the thread
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create a thread that continuously increments a counter.
    const handle_ret = syscall.thread_create(&incrementer, 0, 4);
    if (handle_ret <= 0) {
        t.failWithVal("§2.4.5 thread_create", 1, handle_ret);
        syscall.shutdown();
    }
    const thread_handle: u64 = @bitCast(handle_ret);

    // Wait for the thread to start running.
    t.waitUntilNonZero(&counter);

    // Revoke the thread handle.
    const revoke_ret = syscall.revoke_perm(thread_handle);
    if (revoke_ret != 0) {
        t.failWithVal("§2.4.5 revoke_perm", 0, revoke_ret);
        syscall.shutdown();
    }

    // Verify handle is gone from perm view.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == thread_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            found = true;
            break;
        }
    }
    if (found) {
        t.fail("§2.4.5 handle still in perm view after revoke");
        syscall.shutdown();
    }

    // Record counter and yield to let the thread run more.
    const before = @atomicLoad(u64, &counter, .acquire);
    for (0..10) |_| syscall.thread_yield();
    const after = @atomicLoad(u64, &counter, .acquire);

    // Thread must still be running (counter must have incremented).
    if (after > before) {
        t.pass("§2.4.5");
    } else {
        t.fail("§2.4.5 thread stopped after handle revoke");
    }
    syscall.shutdown();
}
