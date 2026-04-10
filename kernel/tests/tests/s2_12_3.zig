const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.3 — Transferring `HANDLE_SELF` via capability transfer with the `fault_handler` bit set atomically: if the recipient already holds a process handle to the sender, the `fault_handler` bit is added to that existing entry; otherwise a new process handle entry is inserted into the recipient's permissions table with `fault_handler` set.
/// `fault_handler` bit set atomically: (i) inserts / updates the recipient's
/// process handle entry with `fault_handler`, (ii) clears the sender's slot 0
/// `fault_handler` ProcessRights bit (syncUserView called on sender), and
/// (iii) routes all subsequent faults from the sender to the recipient's
/// fault box.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_report_rights_then_fault.ptr),
        children.child_report_rights_then_fault.len,
        child_rights,
    )));

    // First call: child reports pre-transfer slot 0 rights and cap-transfers
    // HANDLE_SELF + fault_handler. The pre-transfer rights MUST still carry
    // the fault_handler bit.
    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.3 first ipc_call");
        syscall.shutdown();
    }
    const pre_rights = reply.words[0];
    const fh_bit_proc: u64 = 0x80;
    if ((pre_rights & fh_bit_proc) == 0) {
        t.fail("§2.12.3 pre-transfer child missing fault_handler bit");
        syscall.shutdown();
    }

    // (a) Sender's slot 0 fault_handler bit CLEARED via the sender's own
    // user view. The second IPC re-reads the child's view after the
    // cap-transfer side-effect.
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.3 second ipc_call");
        syscall.shutdown();
    }
    const post_rights = reply.words[0];
    if ((post_rights & fh_bit_proc) != 0) {
        t.failWithVal("§2.12.3 sender fault_handler bit not cleared", 0, @bitCast(post_rights));
        syscall.shutdown();
    }

    // (b) Recipient (us) now holds a process handle to the child with
    // fault_handler in ProcessHandleRights.
    const fh_bit_phr: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var proc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit_phr) != 0)
        {
            proc_handle = view[i].handle;
            break;
        }
    }
    if (proc_handle == 0) {
        t.fail("§2.12.3 recipient missing fault_handler entry");
        syscall.shutdown();
    }

    // (c) Post-transfer fault from the child arrives in OUR fault box.
    // After the second reply the child null-derefs.
    var fault_msg: syscall.FaultMessage = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (token <= 0) {
        t.failWithVal("§2.12.3 fault_recv token", 1, token);
        syscall.shutdown();
    }
    if (fault_msg.process_handle != proc_handle) {
        t.failWithVal("§2.12.3 wrong source process_handle", @bitCast(proc_handle), @bitCast(fault_msg.process_handle));
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    t.pass("§2.12.3");
    syscall.shutdown();
}
