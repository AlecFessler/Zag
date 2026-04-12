const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.21 — Restart count increments on each restart.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn restartable child that exits immediately — restarts repeatedly
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights)));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Wait for restart count to reach at least 3
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() >= 3) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() >= 3) {
        t.pass("§2.1.21");
    } else {
        t.fail("§2.1.21");
    }
    syscall.shutdown();
}
