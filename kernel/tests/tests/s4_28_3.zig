const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.28.3 — `ioport_write` without `map` right returns `E_PERM`.
/// Transfer a PIO device to child WITHOUT the `map` right.
/// Child tries ioport_write → E_PERM.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a PIO device (type == 1).
    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 1) {
            dev_handle = view[i].handle;
            break;
        }
    }
    if (dev_handle == 0) {
        t.pass("§4.28.3 [SKIP: no PIO device]");
        syscall.shutdown();
    }

    // Spawn child with device_own.
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .device_own = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_ioport.ptr),
        children.child_try_ioport.len,
        child_rights,
    )));

    // Transfer device WITHOUT map right (only grant). Command 1 = ioport_write.
    const dev_rights = (perms.DeviceRegionRights{ .grant = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ 1, dev_handle, dev_rights }, &reply);

    // Ask child for the result.
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.28.3", -2, result);
    syscall.shutdown();
}
