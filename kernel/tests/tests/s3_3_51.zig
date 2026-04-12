const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §3.3.51 — `reply` atomic recv (non-blocking) with no message returns `E_AGAIN`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_reply_recv_noblock.ptr), children.child_reply_recv_noblock.len, child_rights.bits())));
    // First call: child does recv, then reply+recv(non-blocking) → gets E_AGAIN
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply1);
    // Second call: child reports the E_AGAIN result
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply2);
    const child_result: i64 = @bitCast(reply2.words[0]);
    t.expectEqual("§3.3.51", E_AGAIN, child_result);
    syscall.shutdown();
}
