const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const THREAD_STATE_SUSPENDED: u8 = 4;
const THREAD_STATE_READY: u8 = 0;

/// §2.12.23 — On any `fault_reply`, all threads in the target process that are in `.suspended` state are moved to `.ready` and re-enqueued before the action on the faulting thread is applied
/// `.suspended` state are moved to `.ready` and re-enqueued before the action on
/// the faulting thread is applied.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a multi-threaded child that transfers fault_handler then faults.
    // The child spawns a worker thread, then its main thread null-derefs.
    // On the fault, stop-all suspends the worker thread.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_multithread_fault_after_transfer.ptr),
        children.child_multithread_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler for the child via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Wait for the fault to arrive (blocking).
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    if (token < 0) {
        t.fail("§2.12.23 fault_recv failed");
        syscall.shutdown();
    }

    // At this point, the child's worker thread should be in .suspended state
    // due to stop-all. Scan all thread entries and look for any suspended one
    // (skipping slot 1, which is the parent's own initial thread).
    var found_suspended = false;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
            view[i].handle != 0 and
            view[i].handle != @as(u64, @bitCast(token)) and
            view[i].threadState() == THREAD_STATE_SUSPENDED)
        {
            found_suspended = true;
            break;
        }
    }

    // Now reply with FAULT_KILL to resolve the fault. Per §2.12.23, all
    // suspended threads should be moved to .ready before the kill is applied.
    const rc = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);

    if (rc != 0) {
        t.fail("§2.12.23 fault_reply failed");
        syscall.shutdown();
    }

    // After fault_reply, check that the previously suspended thread is no
    // longer suspended — it should have been moved to .ready.
    // Give the kernel a moment to update the perm view.
    syscall.thread_yield();
    syscall.thread_yield();

    var still_suspended = false;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
            view[i].handle != 0 and
            view[i].handle != @as(u64, @bitCast(token)) and
            view[i].threadState() == THREAD_STATE_SUSPENDED)
        {
            still_suspended = true;
            break;
        }
    }

    // The suspended thread should have been resumed (moved to .ready).
    if (found_suspended and !still_suspended) {
        t.pass("§2.12.23");
    } else if (!found_suspended) {
        // Could not confirm the worker was suspended before reply — partial pass.
        t.fail("§2.12.23 worker was not in suspended state before reply");
    } else {
        t.fail("§2.12.23 worker still suspended after fault_reply");
    }
    syscall.shutdown();
}
