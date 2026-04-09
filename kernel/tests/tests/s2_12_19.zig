const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.12.19 — On success, `fault_recv` writes a `FaultMessage` to the provided userspace buffer, transitions the fault box to `pending_reply` state, and returns the fault token (equal to `FaultMessage.thread_handle`) in `rax`
/// buffer, transitions the fault box to pending_reply state, and returns the fault
/// token (equal to FaultMessage.thread_handle) in rax.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child with fault_handler so it can transfer it to us.
    const child_rights = perms.ProcessRights{ .fault_handler = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    )));

    // Let child start and block on recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Call child to trigger cap transfer of HANDLE_SELF with fault_handler.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Child will now null-deref and fault. Give it time.
    syscall.thread_yield();
    syscall.thread_yield();

    // Receive the fault message (blocking).
    var fault_msg: syscall.FaultMessage = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);

    if (token < 0) {
        t.fail("§2.12.19");
        syscall.shutdown();
    }

    // Check 1: FaultMessage was written to buffer — process_handle should be non-zero
    // and match the child's handle in our perm table.
    var found_proc_handle = false;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            if (fault_msg.process_handle == view[i].handle) {
                found_proc_handle = true;
            }
            break;
        }
    }

    // Check 2: Fault token equals FaultMessage.thread_handle.
    const token_u64: u64 = @bitCast(token);
    const token_matches_thread = (token_u64 == fault_msg.thread_handle);

    // Check 3: Fault box is now in pending_reply state — a second fault_recv should
    // return E_BUSY.
    var fault_msg2: syscall.FaultMessage = undefined;
    const rc2 = syscall.fault_recv(@intFromPtr(&fault_msg2), 0);
    const is_pending_reply = (rc2 == E_BUSY);

    if (found_proc_handle and token_matches_thread and is_pending_reply) {
        t.pass("§2.12.19");
    } else {
        t.fail("§2.12.19");
    }

    // Clean up.
    _ = syscall.fault_reply_simple(token_u64, syscall.FAULT_KILL);
    syscall.shutdown();
}
