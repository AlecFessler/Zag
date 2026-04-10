const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.10.13 — `proc_create` with `max_thread_priority` exceeding the parent's own `max_thread_priority` returns `E_PERM`.
///
/// Create a child with ceiling=NORMAL. That child attempts to create a
/// grandchild with ceiling=HIGH (above its own) — should get E_PERM.
/// Also verify that creating at-or-below ceiling succeeds.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .set_affinity = true,
    };

    // Child with ceiling=NORMAL tries to create grandchild with ceiling=HIGH.
    const ch: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_sched_try_create_with_priority.ptr),
        children.child_sched_try_create_with_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_NORMAL,
    ));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply);
    const r: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.10.13 child ceiling=NORMAL, grandchild ceiling=HIGH", E_PERM, r);

    // Same child tries ceiling=NORMAL (at own ceiling) — should succeed or
    // fail for other reasons (bad ELF), but NOT E_PERM.
    const ch2: u64 = @bitCast(syscall.proc_create_with_opts(
        @intFromPtr(children.child_sched_try_create_with_priority.ptr),
        children.child_sched_try_create_with_priority.len,
        child_rights.bits(),
        perms.ThreadHandleRights.full.bits(),
        syscall.PRIORITY_NORMAL,
    ));
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch2, &.{syscall.PRIORITY_NORMAL}, &reply2);
    const r2: i64 = @bitCast(reply2.words[0]);
    // Should not be E_PERM — may be E_INVAL (bad ELF) or positive (success).
    if (r2 != E_PERM) {
        t.pass("§4.10.13 at-ceiling not E_PERM");
    } else {
        t.fail("§4.10.13 at-ceiling should not be E_PERM");
    }

    syscall.shutdown();
}
