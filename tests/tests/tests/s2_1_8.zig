const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.8 — When a device handle is returned (revoke, exit, cleanup), the kernel inserts the handle into the nearest alive ancestor.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle in our perm_view and save its field0 for identification.
    var dev_handle: u64 = 0;
    var dev_field0: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            dev_field0 = view[i].field0;
            break;
        }
    }

    // Spawn child with device_own right.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_device_exit.ptr), children.child_recv_device_exit.len, child_rights.bits())));

    // Transfer device handle to child via IPC call with cap transfer.
    // Device transfer is exclusive — removed from sender.
    const dev_rights = perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true };
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights.bits() }, &reply);

    // Verify device is gone from our perm_view.
    var still_here = false;
    for (0..128) |i| {
        if (view[i].handle == dev_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            still_here = true;
            break;
        }
    }

    if (still_here) {
        t.fail("§2.1.8 [device not transferred]");
        syscall.shutdown();
    }

    // Child exits — device should return to us (nearest alive ancestor).
    // Wait for child to die and device to reappear.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        // Check if the device handle reappeared (may have a new handle ID).
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
                // Verify it's the same device by checking field0/field1 match.
                if (view[i].field0 == dev_field0) {
                    t.pass("§2.1.8");
                    syscall.shutdown();
                }
            }
        }
        syscall.thread_yield();
    }

    t.fail("§2.1.8");
    syscall.shutdown();
}
