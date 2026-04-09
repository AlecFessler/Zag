const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.9.1 — Device access is exclusive (only one process holds the handle at a time).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            break;
        }
    }

    if (dev_handle == 0) {
        t.pass("§2.9.1 [SKIP: no device]");
        syscall.shutdown();
    }

    // Transfer device to child — exclusive, should disappear from our view.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_device_exit.ptr), children.child_recv_device_exit.len, child_rights.bits())));
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    var still_here = false;
    for (0..128) |i| {
        if (view[i].handle == dev_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            still_here = true;
            break;
        }
    }

    if (!still_here) {
        t.pass("§2.9.1");
    } else {
        t.fail("§2.9.1");
    }
    syscall.shutdown();
}
