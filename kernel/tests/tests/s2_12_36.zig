const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;
const E_BUSY: i64 = -11;

/// §2.12.36 — The fault box state is fully independent from the IPC message box state.
/// `fault_recv` and `fault_reply` do not interact with `recv`/`reply` pending state;
/// both boxes may be in `pending_reply` simultaneously.
pub fn main(_: u64) void {
    // Drive the fault box into `pending_reply` state by acquiring an external
    // fault handler relationship with a child that faults, then receiving the
    // fault. This is the only state we need to set up, because if the boxes
    // shared state, an IPC call against the *other* box would observe E_BUSY
    // even though no IPC is pending.
    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§2.12.36 fault_recv", 0, token);
        syscall.shutdown();
    }

    // Confirm the fault box is now in pending_reply (a second non-blocking
    // fault_recv must return E_BUSY).
    var fault_buf2: [256]u8 align(8) = undefined;
    const second_fault = syscall.fault_recv(@intFromPtr(&fault_buf2), 0);
    if (second_fault != E_BUSY) {
        t.failWithVal("§2.12.36 fault_box not pending_reply", E_BUSY, second_fault);
        syscall.shutdown();
    }

    // Independence check: a non-blocking ipc_recv must NOT be poisoned by the
    // fault box being in pending_reply. The msg_box is idle, so it must
    // return E_AGAIN, not E_BUSY.
    var ipc_msg: syscall.IpcMessage = .{};
    const ipc_rc = syscall.ipc_recv(false, &ipc_msg);
    if (ipc_rc != E_AGAIN) {
        t.failWithVal("§2.12.36 ipc_recv leaked fault_box state", E_AGAIN, ipc_rc);
        // Still try to clean up.
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    t.pass("§2.12.36");
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
