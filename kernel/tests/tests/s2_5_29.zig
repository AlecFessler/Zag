const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.29 — The removed `notify_wait` syscall returns `E_INVAL` for any process.
pub fn main(_: u64) void {
    // Spawn child with zero rights
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_notify_wait.ptr),
        children.child_try_notify_wait.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    // Child calls notify_wait(0) — E_INVAL expected since syscall is removed
    t.expectEqual("§2.5.29", syscall.E_INVAL, child_result);
    syscall.shutdown();
}
