const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.24 — Device capability transfer is exclusive (removes from sender).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§3.3.24");
    const dev_handle = dev.handle;

    // Transfer device to child via cap transfer — exclusive, should disappear from our view.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_device_exit.ptr), children.child_recv_device_exit.len, child_rights.bits())));
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Verify device handle is gone from our perm_view (exclusive transfer).
    var still_here = false;
    for (0..128) |i| {
        if (view[i].handle == dev_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            still_here = true;
            break;
        }
    }
    if (still_here) {
        t.fail("§3.3.24");
        syscall.shutdown();
    }

    // Wait for child to exit — device should return to us (nearest alive ancestor).
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    // After child exits, device should have returned to us.
    var returned = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            returned = true;
            break;
        }
    }

    if (returned) {
        t.pass("§3.3.24");
    } else {
        t.fail("§3.3.24");
    }
    syscall.shutdown();
}
