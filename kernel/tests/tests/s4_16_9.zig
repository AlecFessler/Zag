const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §4.16.9 — `send` with no receiver waiting returns `E_AGAIN`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_sleep.ptr),
        children.child_sleep.len,
        child_rights.bits(),
    )));
    // child_sleep never calls ipc_recv, so ipc_send should return E_AGAIN immediately.
    const ret = syscall.ipc_send(child_handle, &.{0x42});
    t.expectEqual("§4.16.9", E_AGAIN, ret);
    syscall.shutdown();
}
