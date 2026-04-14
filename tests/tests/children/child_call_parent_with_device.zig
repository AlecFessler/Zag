const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives device via cap transfer, receives parent handle via cap transfer,
/// then tries to call parent with device cap transfer (child→parent, not parent→child).
/// This should fail because device cap transfer requires parent→child direction.
pub fn main(perm_view_addr: u64) void {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // First recv: device via cap transfer
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    // Find device in our perm view
    var dev_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = entry.handle;
            break;
        }
    }

    // Second recv: parent handle via cap transfer
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    // Find parent handle (process type, not HANDLE_SELF)
    var parent_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
            parent_handle = entry.handle;
            break;
        }
    }

    // Try to call parent with device cap transfer (child→parent direction)
    // This queues since parent isn't in recv. Parent will recv and hit the error.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(parent_handle, &.{ dev_handle, dev_rights }, &reply);
    // If we get here, parent replied (shouldn't happen in the error case, but handle it)
}
