const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.13 — Device handle entries persist across restart.
/// Spawn restartable child_device_restart, transfer a device to it. The child
/// crashes in a loop and restarts. After multiple restarts, verify the device
/// has NOT returned to the parent (it persisted with the child).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle in our perm view.
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
        t.pass("§2.6.13 [SKIP: no device handles in test QEMU]");
        syscall.shutdown();
    }

    // Spawn restartable child_device_restart.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true, .restart = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_device_restart.ptr), children.child_device_restart.len, child_rights.bits())));

    // Transfer device to child via IPC.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Find child slot and wait for restart_count >= 2.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    var attempts: u32 = 0;
    while (attempts < 200000) : (attempts += 1) {
        if (view[slot].processRestartCount() >= 2) break;
        syscall.thread_yield();
    }

    // Device should NOT have returned to us — it persisted with the child across restarts.
    var device_returned = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
            device_returned = true;
            break;
        }
    }

    const child_alive = view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS;
    const restarted = view[slot].processRestartCount() >= 2;

    if (!device_returned and child_alive and restarted) {
        t.pass("§2.6.13");
    } else {
        t.fail("§2.6.13");
    }
    syscall.shutdown();
}
