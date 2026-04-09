const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.31.2 — `thread_resume` requires the `resume` right on `thread_handle`; returns `E_PERM` without it.
pub fn main(_: u64) void {
    // Spawn a child whose initial thread handle (slot 1) has every right except resume.
    const child_proc_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    const thread_rights = perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = false,
        .kill = true,
        .set_affinity = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_report_slot1.ptr),
        children.child_report_slot1.len,
        child_proc_rights.bits(),
        thread_rights.bits(),
    )));

    // Tell the child to call thread_resume on its own slot-1 thread handle.
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call(child_handle, &.{2}, &reply);
    if (ret != 0) {
        t.failWithVal("§4.31.2 ipc_call", 0, ret);
        syscall.shutdown();
    }
    const action_rc: i64 = @bitCast(reply.words[3]);
    t.expectEqual("§4.31.2", E_PERM, action_rc);
    syscall.shutdown();
}
