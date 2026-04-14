const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.16 — Restart is triggered when a process with a restart context terminates by a fault.
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
    // Wait for restart count — child faults, kernel restarts it
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() > 0) {
        t.pass("§2.1.16");
    } else {
        t.fail("§2.1.16");
    }
    syscall.shutdown();
}
