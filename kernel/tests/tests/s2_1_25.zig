const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.25 — Device handle entries persist across restart.
///
/// Spawn a restartable child that receives a device, pins itself, then crashes.
/// After restart, verify:
///   - Device handle persisted (child still has it, not returned to parent).
///   - Core_pin handle was cleared (child reports zero core_pin entries).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.1.25");
    const dev_handle = dev.handle;
    const dev_field0 = dev.field0;

    // Spawn restartable child_pin_then_restart.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .device_own = true, .restart = true, .set_affinity = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_pin_then_restart.ptr), children.child_pin_then_restart.len, child_rights.bits())));

    // Transfer device to child via IPC.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ dev_handle, dev_rights }, &reply);

    // Find child slot and wait for restart_count >= 1.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    var attempts: u32 = 0;
    while (attempts < 200000) : (attempts += 1) {
        if (view[slot].processRestartCount() >= 1) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() < 1) {
        t.fail("§2.1.25 child never restarted");
        syscall.shutdown();
    }

    // IPC to the restarted child to get its report.
    var report: syscall.IpcMessage = .{};
    const ipc_ret = syscall.ipc_call(ch, &.{}, &report);
    if (ipc_ret != 0) {
        t.failWithVal("§2.1.25 ipc_call to restarted child", 0, ipc_ret);
        syscall.shutdown();
    }
    const core_pin_count = report.words[0];
    const device_count = report.words[1];

    // Device should NOT have returned to us — it persisted with the child.
    var device_returned = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
            device_returned = true;
            break;
        }
    }

    const child_alive = view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS;

    if (!device_returned and child_alive and device_count > 0 and core_pin_count == 0) {
        t.pass("§2.1.25");
    } else {
        t.fail("§2.1.25");
    }
    syscall.shutdown();
}
