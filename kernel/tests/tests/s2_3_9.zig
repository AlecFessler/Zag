const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.9 — Device transfer is exclusive (removed from sender on transfer).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device handle in our perm view.
    var device_handle: u64 = 0;
    var device_rights: u16 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            device_handle = view[i].handle;
            device_rights = view[i].rights;
            break;
        }
    }
    if (device_handle == 0) {
        t.fail("§2.3.9");
        syscall.shutdown();
    }
    // Spawn a child with device_own right (required for receiving device handles).
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));
    // Transfer device handle to child.
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call_cap(child_handle, &.{ device_handle, device_rights }, &reply);
    if (ret != 0) {
        t.failWithVal("§2.3.9", 0, ret);
        syscall.shutdown();
    }
    // Verify device handle is removed from parent's perm view.
    var still_has_device = false;
    for (0..128) |i| {
        if (view[i].handle == device_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            still_has_device = true;
            break;
        }
    }
    if (!still_has_device) {
        t.pass("§2.3.9");
    } else {
        t.fail("§2.3.9");
    }
    syscall.shutdown();
}
