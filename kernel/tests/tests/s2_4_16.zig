const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.4.16 — `thread_kill` requires the `kill` right on the thread handle; returns `E_PERM` without it.
pub fn main(_: u64) void {
    // Spawn a child whose slot-1 thread handle has every right EXCEPT kill.
    const child_proc_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    const thread_rights = perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = false,
        .set_affinity = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_report_slot1.ptr),
        children.child_report_slot1.len,
        child_proc_rights.bits(),
        thread_rights.bits(),
    )));

    // Ask the child to call thread_kill on its own slot-1 thread handle.
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call(child_handle, &.{3}, &reply);
    if (ret != 0) {
        t.failWithVal("§2.4.16 ipc_call", 0, ret);
        syscall.shutdown();
    }
    const action_rc: i64 = @bitCast(reply.words[3]);
    t.expectEqual("§2.4.16", E_PERM, action_rc);
    syscall.shutdown();
}
