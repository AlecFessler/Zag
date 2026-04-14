const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.1.18 — A restarting process remains alive throughout (IPC to it does not return `E_BADHANDLE`).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn restartable child_check_data_reload.
    // On first boot: corrupts .data and exits → triggers restart.
    // On second boot: waits for IPC and replies with .data sentinel.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_check_data_reload.ptr),
        children.child_check_data_reload.len,
        child_rights,
    )));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Wait for the child to restart (first boot exits, triggering restart).
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.1.18");
        syscall.shutdown();
    }
    // After restart, IPC to the process should still work (not E_BADHANDLE).
    // The child on second boot waits for an IPC call and replies.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{}, &reply);
    if (rc != E_BADHANDLE and rc == 0) {
        t.pass("§2.1.18");
    } else {
        t.fail("§2.1.18");
    }
    syscall.shutdown();
}
