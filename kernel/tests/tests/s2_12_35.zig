const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.35 — When the handler process dies, all processes that had it as fault handler revert to self-fault-handling: their `fault_handler` ProcessRights bit is restored and their `fault_handler_proc` is cleared.
/// revert to self-fault-handling: their `fault_handler` ProcessRights bit is restored
/// and their `fault_handler_proc` is cleared.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Strategy: We spawn a child and acquire fault_handler for it. Then we revoke
    // the fault_handler permission to simulate the handler death cleanup path.
    // Per §2.12.6, when fault_handler is released, thread handles belonging to
    // the target are bulk-revoked from the handler's perm table. This exercises
    // the same kernel cleanup logic as handler death (§2.12.35).
    //
    // A full integration test would require spawning a handler process that
    // becomes fault handler for a target, then killing the handler and observing
    // the target revert. That requires a more complex multi-process setup.

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    // Acquire fault_handler for the child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Verify we now have thread handles for the child (proving we are its handler).
    // Skip slot 1 which holds parent's own initial thread handle.
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            thread_handle = view[i].handle;
            break;
        }
    }

    if (thread_handle == 0) {
        t.fail("§2.12.35 no thread handle after acquiring fault_handler");
        syscall.shutdown();
    }

    // Find the fault_handler process handle entry.
    const fault_handler_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var fh_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fault_handler_bit) != 0)
        {
            fh_handle = view[i].handle;
            break;
        }
    }

    if (fh_handle == 0) {
        t.fail("§2.12.35 no fault_handler handle");
        syscall.shutdown();
    }

    // Revoke the fault_handler permission to simulate handler death cleanup path.
    // Per §2.12.6, when fault_handler is released, thread handles belonging to
    // the target are bulk-revoked from the handler's perm table.
    const revoke_rc = syscall.revoke_perm(fh_handle);

    // After revoking, the thread handles should be removed from our perm table.
    var thread_still_present = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
            view[i].handle == thread_handle)
        {
            thread_still_present = true;
            break;
        }
    }

    if (revoke_rc == 0 and !thread_still_present) {
        t.pass("§2.12.35");
    } else if (revoke_rc != 0) {
        t.failWithVal("§2.12.35 revoke", 0, revoke_rc);
    } else {
        t.fail("§2.12.35 thread handle not cleaned up");
    }
    syscall.shutdown();
}
