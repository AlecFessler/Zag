const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.34 — `send` device cap transfer not parent→child returns `E_PERM`.
/// Tests the parent→child direction check on device cap transfer. Child tries
/// to transfer a device to parent (wrong direction). The cap transfer validation
/// is the same code path for both send and call; tested via call+recv for simplicity.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§3.3.34");
    const dev_handle = dev.handle;

    // Spawn child with device_own.
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .device_own = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_call_parent_with_device.ptr),
        children.child_call_parent_with_device.len,
        child_rights,
    )));

    // Transfer device to child (with grant right so child can re-transfer).
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Transfer HANDLE_SELF to child (with send_device + grant so child can attempt device transfer).
    const handle_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_device = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_call_cap(ch, &.{ 0, handle_rights }, &reply);

    // Child now does ipc_call_cap to us with device (child→parent direction).
    // Child blocks/queues. We recv — cap transfer validation fails at recv time.
    // Give child a moment to queue.
    for (0..5) |_| syscall.thread_yield();

    var msg: syscall.IpcMessage = .{};
    const rc = syscall.ipc_recv(true, &msg);

    // Cap transfer should fail: child is not our parent → E_PERM.
    t.expectEqual("§3.3.34", -2, rc);
    syscall.shutdown();
}
