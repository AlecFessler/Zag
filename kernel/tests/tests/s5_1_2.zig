const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §5.1.2 — `clock_setwall` requires `ProcessRights.set_time` on slot 0; returns `E_PERM` without it.
pub fn main(_: u64) void {
    // Spawn child WITHOUT set_time right
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_clock_setwall.ptr),
        children.child_try_clock_setwall.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§5.1.2", syscall.E_PERM, child_result);
    syscall.shutdown();
}
