const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.11.13 — `recv` returns `E_BUSY` if a pending reply has not been cleared.
pub fn main(_: u64) void {
    // Use child_recv_busy: it receives a call, tries recv again → E_BUSY, reports result
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_busy.ptr), children.child_recv_busy.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.11.13", E_BUSY, child_result);
    syscall.shutdown();
}
