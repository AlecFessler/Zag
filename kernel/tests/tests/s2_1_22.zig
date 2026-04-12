const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.22 — Fault reason is recorded in slot 0 `field0` on restart.
/// Per §2.6.26, fault reason is written to BOTH the child's own slot 0 AND the
/// parent's entry for the child. Verified here from the parent side; the child's
/// own slot 0 is verified by child_stack_overflow_restart's internal logic.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn restartable child that faults (stack overflow)
    const child_rights = (perms.ProcessRights{ .restart = true, .spawn_thread = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_stack_overflow.ptr), children.child_stack_overflow.len, child_rights)));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Wait for restart — crash reason should be stack_overflow
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    // Parent's view should show crash reason = stack_overflow after restart
    if (view[slot].processCrashReason() == .stack_overflow and view[slot].processRestartCount() > 0) {
        t.pass("§2.1.22");
    } else {
        t.fail("§2.1.22");
    }
    syscall.shutdown();
}
