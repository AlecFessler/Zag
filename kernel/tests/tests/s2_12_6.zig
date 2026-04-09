const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.6 — When `fault_handler` is released or the handler process dies, all thread handles belonging to the target are bulk-revoked from the handler's permissions table and `syncUserView` is called on the handler
/// are bulk-revoked from the handler's permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child with fault_handler right.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .fault_handler = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    )));

    // Acquire fault_handler — child transfers HANDLE_SELF with fault_handler bit.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // After acquiring fault_handler, we should have thread handle(s) for the child (§2.12.4).
    // Skip slot 1 which is parent's own initial thread.
    var thread_count_with_handler: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_count_with_handler += 1;
        }
    }

    // Find the process handle that has fault_handler right and revoke it.
    // This releases our fault_handler relationship, which should bulk-revoke thread handles.
    const fault_handler_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var fault_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fault_handler_bit) != 0)
        {
            fault_handle = view[i].handle;
            break;
        }
    }

    if (fault_handle == 0) {
        t.fail("§2.12.6");
        syscall.shutdown();
    }

    // Revoke the process handle that carries fault_handler — releases the relationship.
    _ = syscall.revoke_perm(fault_handle);

    // After revoking, thread handles for the target should be gone.
    // Skip slot 1 which is parent's own initial thread.
    var thread_count_after: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_count_after += 1;
        }
    }

    // We had thread handles while holding fault_handler, now they should be revoked.
    if (thread_count_with_handler > 0 and thread_count_after == 0) {
        t.pass("§2.12.6");
    } else {
        t.failWithVal("§2.12.6", 0, @bitCast(thread_count_after));
    }
    syscall.shutdown();
}
