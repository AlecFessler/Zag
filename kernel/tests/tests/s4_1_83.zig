const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.83 — `pmu_start` requires `ProcessRights.pmu` on slot 0; returns `E_PERM` without it.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_pmu_all.ptr),
        children.child_try_pmu_all.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const start_rc: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.1.83", syscall.E_PERM, start_rc);
    syscall.shutdown();
}
