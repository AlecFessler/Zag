const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.79 — `pmu_info` requires no rights and is callable by any process.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_pmu_info.ptr),
        children.child_try_pmu_info.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    const rc: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.1.79", syscall.E_OK, rc);
    syscall.shutdown();
}
