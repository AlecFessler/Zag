const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.27 — The kernel issues a futex wake on the parent's user view `field0` for a restarted child.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights)));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Record field0 before child restarts (should be 0 initially).
    const initial_field0 = @atomicLoad(u64, &view[slot].field0, .acquire);
    // futex_wait: block until field0 changes (kernel wakes us on restart).
    // Returns E_AGAIN if value already changed (child restarted before we waited).
    _ = syscall.futex_wait(&view[slot].field0, initial_field0, 5_000_000_000);
    // If futex_wait timed out but the child hasn't restarted yet, poll briefly.
    var attempts: u32 = 0;
    while (view[slot].processRestartCount() == 0 and attempts < 100000) : (attempts += 1) {
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() > 0) {
        t.pass("§2.6.27");
    } else {
        t.fail("§2.6.27");
    }
    syscall.shutdown();
}
