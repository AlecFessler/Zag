const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §4.1.21 — `fault_reply` returns `E_NOENT` if the fault token does not match the currently pending thread (i.e., the thread was killed externally while the fault was pending).
///
/// A .faulted thread cannot be killed via `thread_kill` (§2.4.17 / §4.32.4
/// return E_BUSY), and revoking the process handle tears down the
/// fault-handler relationship (releaseFaultHandler) which drains the
/// pending_reply state and would yield E_INVAL rather than E_NOENT.
///
/// The kernel's E_NOENT path fires whenever the faulting thread's handle
/// is no longer locatable in the handler's perm table between fault_recv
/// and fault_reply. We exercise that path directly by revoking the
/// faulting thread's perm handle (revoke_perm on a thread entry is a
/// pure handle clear per §2.4.5 and the kernel's .thread case — it does
/// not touch the fault box). The pending_reply state is preserved, but
/// findThreadHandle(pending) returns null, matching the kernel comment
/// "If the source thread was killed externally between fault_recv and
/// fault_reply, the handle was cleared" — same observable path.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler via cap transfer; child then null-derefs.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault — token is the faulting thread's handle in our
    // perm table.
    var fault_msg: syscall.FaultMessage = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (token <= 0) {
        t.fail("§4.1.21 fault_recv failed");
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);

    // Sanity check: the thread entry must currently exist in our view.
    var thread_present_before = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle == token_u) {
            thread_present_before = true;
            break;
        }
    }
    if (!thread_present_before) {
        t.fail("§4.1.21 thread entry missing before kill");
        syscall.shutdown();
    }

    // Revoke the faulting thread's perm handle directly — .thread case
    // of sysRevokePerm is a pure handle clear that does NOT touch the
    // fault box. This drives findThreadHandle(pending) to null, which
    // is the exact path §2.12.21's E_NOENT comes through.
    const kr = syscall.revoke_perm(token_u);
    if (kr != 0) {
        t.failWithVal("§4.1.21 revoke_perm", 0, kr);
        syscall.shutdown();
    }

    // Now fault_reply with the ORIGINAL valid token — it no longer
    // matches the currently pending thread (it was killed), so per
    // §4.1.21 this must return E_NOENT.
    const rc = syscall.fault_reply_simple(token_u, syscall.FAULT_RESUME);
    t.expectEqual("§4.1.21", E_NOENT, rc);
    syscall.shutdown();
}
