const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// `set_priority` with a priority exceeding the process's `max_thread_priority` returns `E_PERM`.
pub fn main(_: u64) void {
    // Spawn child with max_thread_priority = NORMAL. Child tries HIGH → E_PERM.
    const rights = (perms.ProcessRights{ .set_affinity = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_opts(
        @intFromPtr(children.child_sched_set_priority.ptr),
        children.child_sched_set_priority.len,
        rights,
        (perms.ThreadHandleRights.full).bits(),
        syscall.PRIORITY_NORMAL,
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply);
    const result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.15.2", E_PERM, result);
    syscall.shutdown();
}
