const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.0.3 — Every process has a `max_thread_priority` ceiling.
///
/// Create a child with max_thread_priority=NORMAL. The child tries to set
/// priority to HIGH (above ceiling) — should get E_PERM. Then tries NORMAL
/// (at ceiling) — should succeed.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .set_affinity = true, .spawn_thread = true };
    const ch: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_try_set_priority.ptr),
        children.child_try_set_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_NORMAL,
    ));

    // Ask child to try HIGH — should fail with E_PERM.
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply1);
    const r1: i64 = @bitCast(reply1.words[0]);
    t.expectEqual("§2.0.3 HIGH above ceiling", E_PERM, r1);

    syscall.shutdown();
}
