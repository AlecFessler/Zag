const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.35 — On restart of a process that has an external fault handler: all thread handles for that process are bulk-revoked from the handler's permissions table; the fresh initial thread handle is immediately inserted into the handler's permissions table with full `ThreadHandleRights`; the `fault_handler` relationship (fault_handler_proc pointer) persists across restart without requiring re-transfer
/// handles for that process are bulk-revoked from the handler's permissions table; the
/// fresh initial thread handle is immediately inserted into the handler's permissions
/// table with full ThreadHandleRights; the fault_handler relationship persists across
/// restart without requiring re-transfer.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a restartable child with fault_handler right.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .restart = true,
        .fault_handler = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    )));

    // Acquire fault_handler — child transfers HANDLE_SELF with fault_handler bit.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Record the thread handle from the initial acquisition.
    // Skip slot 1 (parent's own initial thread).
    var initial_thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            initial_thread_handle = view[i].handle;
            break;
        }
    }

    // Find the process handle with fault_handler right.
    const fault_handler_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var fault_proc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fault_handler_bit) != 0)
        {
            fault_proc_handle = view[i].handle;
            break;
        }
    }

    // Kill the child's thread to trigger restart (child is restartable).
    if (initial_thread_handle != 0) {
        _ = syscall.thread_kill(initial_thread_handle);
    }

    // Yield to allow the restart to complete.
    syscall.thread_yield();
    syscall.thread_yield();
    syscall.thread_yield();

    // After restart, verify:
    // 1. fault_handler relationship persists (process handle still has fault_handler right).
    var still_has_fault_handler = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle == fault_proc_handle and
            (view[i].rights & fault_handler_bit) != 0)
        {
            still_has_fault_handler = true;
            break;
        }
    }

    // 2. A fresh thread handle exists with full ThreadHandleRights.
    // Skip slot 1 (parent's own thread).
    var has_thread_handle = false;
    const full_thread_rights: u16 = @truncate(perms.ThreadHandleRights.full.bits());
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
            (view[i].rights & full_thread_rights) == full_thread_rights)
        {
            has_thread_handle = true;
            break;
        }
    }

    if (still_has_fault_handler and has_thread_handle) {
        t.pass("§2.6.35");
    } else {
        t.fail("§2.6.35");
    }
    syscall.shutdown();
}
