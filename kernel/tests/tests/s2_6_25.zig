const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.25 — When a fault kills a process, the crash reason is recorded.
/// Verifies via the parent's perm_view entry for the child (not the child's own slot 0).
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
    // Wait for restart — kernel records crash reason in parent's entry for the child
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    // Parent's view entry for the child must show a non-zero crash reason (fault)
    const reason = view[slot].processCrashReason();
    if (view[slot].processRestartCount() > 0 and reason != .none and reason != .normal_exit) {
        t.pass("§2.6.25");
    } else {
        t.fail("§2.6.25");
    }
    syscall.shutdown();
}
