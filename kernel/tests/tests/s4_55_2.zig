const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.2 — `sys_info` requires no rights and is callable by any process.
///
/// Spawn a child with an all-zero `ProcessRights` bitmap (no spawn, no
/// mem_reserve, no pmu, nothing) and have it call `sys_info` with a valid
/// `info_ptr` and null `cores_ptr`. The child reports the return code back
/// to the parent via IPC. §4.55.2 says any process may call sys_info
/// regardless of rights, so the expected value is `E_OK`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_sys_info.ptr),
        children.child_try_sys_info.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    const rc: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.55.2", syscall.E_OK, rc);
    syscall.shutdown();
}
