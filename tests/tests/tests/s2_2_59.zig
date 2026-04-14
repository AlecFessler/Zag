const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.2.59 — `thread_kill` requires the `kill` right on `thread_handle`; returns `E_PERM` without it.
///
/// Spawn a child whose own initial thread handle lacks `ThreadHandleRights.kill`;
/// the child then calls `thread_kill(thread_self())` and reports the result.
pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{}).bits();
    const thread_rights = (perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = false,
    }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_self_kill.ptr),
        children.child_self_kill.len,
        child_rights,
        thread_rights,
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const rc: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.2.59", E_PERM, rc);
    syscall.shutdown();
}
