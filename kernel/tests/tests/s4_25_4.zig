const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.25.4 — `dma_map` without `dma` right returns `E_PERM`.
/// Transfer an MMIO device to child WITHOUT the `dma` right.
/// Child tries dma_map → E_PERM.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find an MMIO device (type == 0).
    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 0) {
            dev_handle = view[i].handle;
            break;
        }
    }
    if (dev_handle == 0) {
        t.pass("§4.25.4 [SKIP: no MMIO device]");
        syscall.shutdown();
    }

    // Spawn child with device_own + shm_create (needs SHM for dma_map).
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .device_own = true, .shm_create = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_dma_map.ptr),
        children.child_try_dma_map.len,
        child_rights,
    )));

    // Transfer device WITHOUT dma right (only map + grant).
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Ask child for the result.
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.25.4", -2, result);
    syscall.shutdown();
}
