const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.24 — A process can detect restart via slot 0 `field0` (crash_reason or restart_count non-zero).
/// child_check_bss uses its own view[0].processRestartCount() to branch between first boot
/// and restart behavior — proving the child can detect its own restart via slot 0.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child_check_bss. On first boot it writes a sentinel to BSS.
    // On restart, it reads view[0].processRestartCount() to detect restart,
    // then enters ipc_recv and replies with its BSS value.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_check_bss.ptr),
        children.child_check_bss.len,
        child_rights,
    )));

    // Find child's slot.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // Wait for restart.
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.6.24");
        syscall.shutdown();
    }

    // Call the child — it branched on restart_count in its own slot 0, proving
    // it can detect its own restart. It replies with its BSS sentinel value
    // (should be 0, proving BSS was re-zeroed, which requires restart detection to verify).
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{}, &reply);
    // Child successfully detected restart (entered the restart_count > 0 branch) and replied.
    if (rc == 0) {
        t.pass("§2.6.24");
    } else {
        t.fail("§2.6.24");
    }
    syscall.shutdown();
}
