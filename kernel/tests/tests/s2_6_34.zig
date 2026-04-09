const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.34 — Non-restartable processes in recursive kill die; device handles return up tree.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle.
    var dev_handle: u64 = 0;
    var dev_field0: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            dev_field0 = view[i].field0;
            break;
        }
    }
    if (dev_handle == 0) {
        t.pass("§2.6.34");
        syscall.shutdown();
    }

    // Spawn non-restartable child_ipc_server WITH device_own.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_server.ptr),
        children.child_ipc_server.len,
        child_rights.bits(),
    )));

    // Transfer device to child via IPC cap transfer (ipc_call blocks until delivered).
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);
    if (call_rc != 0) {
        t.failWithVal("§2.6.34 cap_xfer", 0, call_rc);
        syscall.shutdown();
    }

    // Verify device transferred (gone from parent).
    var device_present = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
            device_present = true;
            break;
        }
    }
    if (device_present) {
        t.fail("§2.6.34 not_transferred");
        syscall.shutdown();
    }

    // Wait for child to re-enter recv (it just replied and is looping back).
    for (0..20) |_| syscall.thread_yield();

    // Kill non-restartable child via revoke (has kill right from proc_create).
    _ = syscall.revoke_perm(ch);

    // Wait for device to return. The child's cleanup is async if its thread was
    // running on another core when killed — scheduler must catch the exited thread.
    var device_returned = false;
    var wait: u32 = 0;
    while (wait < 500000) : (wait += 1) {
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
                device_returned = true;
                break;
            }
        }
        if (device_returned) break;
        syscall.thread_yield();
    }
    if (device_returned) {
        t.pass("§2.6.34");
    } else {
        t.fail("§2.6.34 not_returned");
    }
    syscall.shutdown();
}
