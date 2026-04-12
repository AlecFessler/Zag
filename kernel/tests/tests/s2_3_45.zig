const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.45 — `mem_mmio_map` without `map` right returns `E_PERM`.
/// Transfer an MMIO device to child WITHOUT the `map` right.
/// Child tries mem_mmio_map → E_PERM.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.3.45");
    const dev_handle = dev.handle;

    // Spawn child with device_own + mem_reserve (needs mem_reserve for mem_mmio_map).
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .device_own = true, .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_mmio_map.ptr),
        children.child_try_mmio_map.len,
        child_rights,
    )));

    // Transfer device WITHOUT map right (only grant + dma).
    const dev_rights = (perms.DeviceRegionRights{ .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Ask child for the result.
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§2.3.45", -2, result);
    syscall.shutdown();
}
