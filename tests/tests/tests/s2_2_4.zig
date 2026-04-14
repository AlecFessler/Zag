const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.4 — `max_thread_priority` is set at `proc_create` time as an explicit parameter and is never implicitly inherited.
///
/// Create two children with different ceilings; verify each respects its own
/// ceiling independently.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .set_affinity = true, .spawn_thread = true };

    // Child 1: ceiling = NORMAL. Setting HIGH should fail.
    const ch1: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_try_set_priority.ptr),
        children.child_try_set_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_NORMAL,
    ));
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch1, &.{syscall.PRIORITY_HIGH}, &reply1);
    const r1: i64 = @bitCast(reply1.words[0]);
    t.expectEqual("§2.2.4 child1 ceiling=NORMAL, try HIGH", @as(i64, -2), r1);

    // Child 2: ceiling = HIGH. Setting HIGH should succeed.
    const ch2: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_try_set_priority.ptr),
        children.child_try_set_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_HIGH,
    ));
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch2, &.{syscall.PRIORITY_HIGH}, &reply2);
    const r2: i64 = @bitCast(reply2.words[0]);
    t.expectOk("§2.2.4 child2 ceiling=HIGH, try HIGH", r2);

    syscall.shutdown();
}
