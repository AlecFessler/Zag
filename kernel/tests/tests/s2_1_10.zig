const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.10 — A process mid-restart is alive and is a valid device handle return destination.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.1.10");
    const dev_handle = dev.handle;
    const dev_field0 = dev.field0;

    // Spawn restartable child (child_device_restart — receives device, crashes in a hot loop).
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true, .restart = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_device_restart.ptr), children.child_device_restart.len, child_rights.bits())));

    // Transfer device to child via IPC.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Wait for a few restarts so we know the child went through mid-restart multiple times.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    // Wait until restart_count >= 3.
    var attempts: u32 = 0;
    while (attempts < 200000) : (attempts += 1) {
        if (view[slot].processRestartCount() >= 3) break;
        syscall.thread_yield();
    }

    // Device should NOT have returned to us — child is alive (mid-restart counts as alive).
    var device_returned = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
            device_returned = true;
            break;
        }
    }

    if (!device_returned) {
        t.pass("§2.1.10");
    } else {
        t.fail("§2.1.10");
    }
    syscall.shutdown();
}
