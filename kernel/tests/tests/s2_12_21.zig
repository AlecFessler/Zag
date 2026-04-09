const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §2.12.21 — `fault_reply` returns `E_NOENT` if the fault token does not match the currently pending thread (i.e., the thread was killed externally while the fault was pending)
/// the currently pending thread.
pub fn main(_: u64) void {
    // Spawn a child that transfers fault_handler to us, then faults.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Call the child to acquire fault_handler via cap transfer; child then faults.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault — this puts the fault box into pending_reply state.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    if (token < 0) {
        t.fail("§2.12.21 fault_recv failed");
        syscall.shutdown();
    }

    // 5. Reply with a wrong token (token + 1) — should return E_NOENT.
    const wrong_token: u64 = @as(u64, @bitCast(token)) + 1;
    const rc = syscall.fault_reply_simple(wrong_token, syscall.FAULT_RESUME);
    t.expectEqual("§2.12.21", E_NOENT, rc);
    syscall.shutdown();
}
