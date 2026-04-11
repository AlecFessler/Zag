const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.53.3 — `pmu_reset` requires the `pmu` right on `thread_handle`; returns `E_PERM` without it.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .pmu = true };
    const thread_rights = perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = true,
    };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_pmu_no_thread_right.ptr),
        children.child_pmu_no_thread_right.len,
        child_rights.bits(),
        thread_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const reset_rc: i64 = @bitCast(reply.words[2]);
    t.expectEqual("§4.53.3", syscall.E_PERM, reset_rc);
    syscall.shutdown();
}
