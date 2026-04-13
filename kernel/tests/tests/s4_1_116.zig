const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.116 — Transferring `HANDLE_SELF` via capability transfer with the `fault_handler` bit set requires the sender to currently hold `ProcessRights.fault_handler` on its slot 0; a sender without that right receives `E_PERM` from the originating IPC syscall and no state on sender, target, or any perm table is modified.
pub fn main(_: u64) void {
    // Spawn child WITHOUT the `fault_handler` ProcessRights bit on slot 0.
    // The child will attempt to grant `fault_handler` via ipc_reply_cap on
    // HANDLE_SELF — the kernel must reject this with E_PERM because the
    // child does not hold the right it is attempting to transfer.
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    )));

    // Let the child start and block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{}, &reply);

    // Parent's ipc_call must observe E_PERM from transferCapability in the
    // replier's sysIpcReply path.
    if (rc != syscall.E_PERM) {
        t.fail("§4.1.116");
        syscall.shutdown();
    }

    t.pass("§4.1.116");
    syscall.shutdown();
}
