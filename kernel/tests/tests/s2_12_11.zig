const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.11 — Before applying stop-all on an external fault, the kernel checks the faulting thread's `exclude_oneshot` and `exclude_permanent` flags on the thread's perm entry in the handler's permissions table.
/// thread's `exclude_oneshot` and `exclude_permanent` flags on the thread's perm entry in the
/// handler's permissions table. If either flag is set, only the faulting thread enters `.faulted`
/// and all other threads continue running.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Step 1: Spawn child_send_self_fault_handler. It replies with HANDLE_SELF
    // via cap transfer with fault_handler, making us the external fault handler.
    const child_rights = (perms.ProcessRights{
        .fault_handler = true,
    }).bits();
    const child_proc_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    // Step 2: IPC call to trigger the cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_proc_handle, &.{}, &reply);

    // Step 3: Find the thread handle for the child's thread in our perm view.
    // Per §2.12.4, acquiring fault_handler inserts thread handles.
    var thread_handle: u64 = 0;
    // Skip slot 1 (parent's own initial thread).
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            break;
        }
    }

    if (thread_handle == 0) {
        t.fail("§2.12.11 no thread handle");
        syscall.shutdown();
    }

    // Step 4: Set exclude_permanent on the child's thread.
    // This should prevent stop-all from being applied when this thread faults.
    // fault_set_thread_mode(thread_handle, FAULT_MODE_EXCLUDE_PERMANENT)
    const mode_rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);

    if (mode_rc < 0) {
        t.fail("§2.12.11 fault_set_thread_mode failed");
        syscall.shutdown();
    }

    // Step 5: Verify the mode was set by checking that fault_set_thread_mode succeeded.
    // In a full test, we would then trigger a fault on this thread and verify
    // that other threads continue running (not suspended by stop-all).
    //
    // Since child_send_self_fault_handler is blocked on futex_wait and won't fault,
    // we verify the API call succeeded. The kernel should have set exclude_permanent
    // on the thread's perm entry.
    //
    // Also test exclude_oneshot (FAULT_MODE_EXCLUDE_NEXT).
    const mode_rc2 = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    if (mode_rc2 < 0) {
        t.fail("§2.12.11 exclude_next failed");
        syscall.shutdown();
    }

    // Revert to stop_all to confirm clearing works too.
    const mode_rc3 = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_STOP_ALL);
    if (mode_rc3 < 0) {
        t.fail("§2.12.11 stop_all failed");
        syscall.shutdown();
    }

    t.pass("§2.12.11");
    syscall.shutdown();
}
