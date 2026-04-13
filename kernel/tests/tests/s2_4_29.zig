const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.29 — `notify_wait` requires no rights and is callable by any process.
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
    // Child calls notify_wait(0) with no pending notifications — E_AGAIN expected
    t.expectEqual("§2.4.29", syscall.E_AGAIN, child_result);
    syscall.shutdown();
}
