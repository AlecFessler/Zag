const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.16.1 — `send` returns `E_OK` on successful delivery.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_server.ptr),
        children.child_ipc_server.len,
        child_rights.bits(),
    )));
    // Do a round-trip call first to ensure child is in recv loop.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{0}, &reply);
    // After reply, child loops back to recv. Yield to let it enter recv.
    for (0..10) |_| syscall.thread_yield();
    const ret = syscall.ipc_send(child_handle, &.{0x42});
    t.expectEqual("§4.16.1", E_OK, ret);
    syscall.shutdown();
}
