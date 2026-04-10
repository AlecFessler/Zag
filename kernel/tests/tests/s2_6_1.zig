const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;
const E_AGAIN: i64 = -9;

/// §2.6.1 — Restart is triggered when a process with a restart context terminates by voluntary exit (last thread calls `thread_exit`).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn a restartable child that exits normally — it should restart
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights)));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Block on the parent view `field0` — per §2.6.27 the kernel issues a
    // futex wake on this cell when the child restarts. E_OK = woken by
    // kernel; E_AGAIN = field0 already changed before we entered wait.
    const initial_field0 = @atomicLoad(u64, &view[slot].field0, .acquire);
    const wait_rc = syscall.futex_wait(&view[slot].field0, initial_field0, 5_000_000_000);
    if (wait_rc != E_OK and wait_rc != E_AGAIN) {
        t.failWithVal("§2.6.1 futex_wait", E_OK, wait_rc);
        syscall.shutdown();
    }
    if (view[slot].processRestartCount() > 0) {
        t.pass("§2.6.1");
    } else {
        t.fail("§2.6.1");
    }
    syscall.shutdown();
}
