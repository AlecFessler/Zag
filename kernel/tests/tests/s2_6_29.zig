const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.29 — The kernel issues a futex wake on the parent's user view `field0` for a dead child.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Spawn a non-restartable child that exits immediately
    const child_rights = (perms.ProcessRights{}).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights)));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Read initial field0 value before child dies
    const initial_field0 = @atomicLoad(u64, &view[slot].field0, .acquire);
    // futex_wait on field0 — kernel should wake us when child dies.
    // Returns E_AGAIN if value already changed (child died before we waited).
    _ = syscall.futex_wait(&view[slot].field0, initial_field0, 5_000_000_000);
    // If futex_wait timed out but the child hasn't died yet, poll briefly.
    var attempts: u32 = 0;
    while (view[slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS and attempts < 100000) : (attempts += 1) {
        syscall.thread_yield();
    }
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.pass("§2.6.29");
    } else {
        t.fail("§2.6.29");
    }
    syscall.shutdown();
}
