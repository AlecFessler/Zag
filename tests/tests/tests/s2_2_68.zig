const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.2.68 — `set_priority` requires `ProcessRights.set_affinity` on slot 0; returns `E_PERM` if absent.
pub fn main(_: u64) void {
    // Spawn child WITHOUT ProcessRights.set_affinity.
    const rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_sched_set_priority.ptr),
        children.child_sched_set_priority.len,
        rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{syscall.PRIORITY_NORMAL}, &reply);
    const result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.2.68", E_PERM, result);
    syscall.shutdown();
}
