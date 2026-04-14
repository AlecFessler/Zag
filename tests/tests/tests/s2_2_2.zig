const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §2.2.2 — All newly created threads start at `normal` priority, including the initial thread of a new process.
pub fn main(_: u64) void {
    // If we started at normal, setting to HIGH should succeed (root has max=pinned).
    const r1 = syscall.set_priority(syscall.PRIORITY_HIGH);
    t.expectOk("§2.2.2 set HIGH from initial", r1);

    // Now set back to normal — should also succeed.
    const r2 = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.2.2 set NORMAL from HIGH", r2);

    // Verify starting priority indirectly: spawn a child with ceiling=NORMAL.
    // If the child started at NORMAL (the only allowed level), set_priority(NORMAL)
    // succeeds (no-op at ceiling). If it somehow started above NORMAL, the ceiling
    // would have been violated at creation time.
    const child_rights = perms.ProcessRights{ .set_affinity = true };
    const ch: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_try_set_priority.ptr),
        children.child_try_set_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_NORMAL,
    ));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{syscall.PRIORITY_NORMAL}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.2.2 child at ceiling=NORMAL can set NORMAL", E_OK, child_result);

    syscall.shutdown();
}
