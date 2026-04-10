const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §2.12.21 — `fault_reply` returns `E_NOENT` if the fault token does not match the currently pending thread (i.e., the thread was killed externally while the fault was pending).
/// match the currently pending thread (i.e., the thread was killed
/// externally while the fault was pending).
///
/// Strong test: use the ORIGINAL valid token after externally killing the
/// faulting thread via `thread_kill`. This exercises the spec scenario
/// exactly — rather than the previous weak test which passed `token+1`
/// (a bogus token).
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
        t.fail("§2.12.21 fault_recv failed");
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);

    // The token IS the thread handle for §2.12.14. Use thread_kill to
    // externally kill the faulting thread while the fault is pending.
    // Sanity check: the thread entry must currently exist in our view.
    var thread_present_before = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle == token_u) {
            thread_present_before = true;
            break;
        }
    }
    if (!thread_present_before) {
        t.fail("§2.12.21 thread entry missing before kill");
        syscall.shutdown();
    }

    const kr = syscall.thread_kill(token_u);
    if (kr != 0) {
        t.failWithVal("§2.12.21 thread_kill", 0, kr);
        syscall.shutdown();
    }

    // Now fault_reply with the ORIGINAL valid token — it no longer
    // matches the currently pending thread (it was killed), so per
    // §2.12.21 this must return E_NOENT.
    const rc = syscall.fault_reply_simple(token_u, syscall.FAULT_RESUME);
    t.expectEqual("§2.12.21", E_NOENT, rc);
    syscall.shutdown();
}
