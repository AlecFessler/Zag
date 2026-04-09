const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.3 — Transferring `HANDLE_SELF` via capability transfer with the `fault_handler` bit set atomically: if the recipient already holds a process handle to the sender, the `fault_handler` bit is added to that existing entry; otherwise a new process handle entry is inserted into the recipient's permissions table with `fault_handler` set.
/// atomically transfers fault handling to the recipient.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child with fault_handler ProcessRight so it can transfer it.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .fault_handler = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    )));

    // Call the child — it replies with HANDLE_SELF via cap transfer with fault_handler bit.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // After the transfer, we should have a process handle entry with fault_handler right set.
    // The child transferred its HANDLE_SELF with fault_handler, so the kernel should have
    // either added fault_handler to our existing handle or created a new one.
    // Scan perm_view for a process entry with fault_handler bit in rights.
    const fault_handler_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var found = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fault_handler_bit) != 0)
        {
            found = true;
            break;
        }
    }

    if (found) {
        t.pass("§2.12.3");
    } else {
        t.fail("§2.12.3");
    }
    syscall.shutdown();
}
