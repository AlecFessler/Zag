const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.0.5 — A parent cannot grant a child a `max_thread_priority` higher than its own.
///
/// Create a child with ceiling=NORMAL. That child tries to proc_create a
/// grandchild with ceiling=HIGH — should return E_PERM.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{
        .set_affinity = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
    };
    const ch: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_sched_try_create_with_priority.ptr),
        children.child_sched_try_create_with_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_NORMAL,
    ));

    // Ask child (ceiling=NORMAL) to create grandchild with ceiling=HIGH.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply);
    const r: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.0.5 child ceiling=NORMAL, create grandchild ceiling=HIGH", E_PERM, r);

    syscall.shutdown();
}
