const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.11.18 — The process must call `reply` before calling `recv` again.
pub fn main(_: u64) void {
    // child_recv_busy: recv (pending_reply), then tries recv again → E_BUSY
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_busy.ptr), children.child_recv_busy.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.11.18", E_BUSY, child_result);
    syscall.shutdown();
}
