const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.32 — BSS is decommitted on restart.
/// Spawns a child that writes a sentinel to a BSS global on first boot, then exits.
/// After restart, the parent calls the child via IPC; the child replies with the
/// current value of the BSS global. If BSS was properly decommitted, the value is 0.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child_check_bss.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_check_bss.ptr),
        children.child_check_bss.len,
        child_rights,
    )));

    // Find child slot in perm_view.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // Wait for the child to restart (restart_count > 0 means it exited once and rebooted).
    var attempts: u32 = 0;
    while (view[slot].processRestartCount() == 0 and attempts < 200000) : (attempts += 1) {
        syscall.thread_yield();
    }

    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.1.32 child did not restart");
        syscall.shutdown();
        return;
    }

    // Call the child — it replies with the value of its BSS sentinel.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // BSS should be zeroed after restart (decommitted and demand-faulted fresh).
    if (reply.words[0] != 0) {
        t.fail("§2.1.32");
        syscall.shutdown();
    }
    t.pass("§2.1.32");
    syscall.shutdown();
}
