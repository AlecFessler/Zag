const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.16.7 — `send` device cap transfer: target lacks `device_own` returns `E_PERM`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.16.7");
    const dev_handle = dev.handle;

    // Spawn child_ipc_server WITHOUT device_own.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Sync: do a round-trip call to ensure child is in recv loop.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{0}, &reply);

    // Child loops back to recv. Yield to let it enter recv.
    for (0..10) |_| syscall.thread_yield();
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    const rc = syscall.ipc_send_cap(ch, &.{ dev_handle, dev_rights });
    t.expectEqual("§4.16.7", E_PERM, rc);
    syscall.shutdown();
}
