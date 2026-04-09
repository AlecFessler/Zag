const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §2.11.20 — Non-blocking atomic recv returns `E_AGAIN` if no message is queued.
pub fn main(_: u64) void {
    // child_reply_recv_noblock: recv → reply_recv(non-blocking) → E_AGAIN → recv → reply(E_AGAIN)
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_reply_recv_noblock.ptr), children.child_reply_recv_noblock.len, child_rights.bits())));
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply1);
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply2);
    const child_result: i64 = @bitCast(reply2.words[0]);
    t.expectEqual("§2.11.20", E_AGAIN, child_result);
    syscall.shutdown();
}
