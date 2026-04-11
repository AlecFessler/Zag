const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.17 — The kernel updates the user view on every permissions table mutation (insert, remove, type change).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Insert: create a VM reservation and check it appears.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    var found_after_insert = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            found_after_insert = true;
            break;
        }
    }
    // Remove: revoke and check it disappears.
    _ = syscall.revoke_perm(handle);
    var found_after_remove = false;
    for (0..128) |i| {
        if (view[i].handle == handle) {
            found_after_remove = true;
            break;
        }
    }

    // Type change: spawn a non-restartable child and let it exit. The kernel
    // converts the `process` entry to `dead_process` in place — a type-change
    // mutation that must also sync the user view.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights.bits(),
    )));
    var child_slot: usize = 128;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            child_slot = i;
            break;
        }
    }
    if (child_slot == 128) {
        t.fail("§2.1.17 child process entry not found after insert");
        syscall.shutdown();
    }
    var iters: u32 = 0;
    var saw_type_change = false;
    while (iters < 100000) : (iters += 1) {
        if (view[child_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS and
            view[child_slot].handle == child_handle)
        {
            saw_type_change = true;
            break;
        }
        syscall.thread_yield();
    }

    if (found_after_insert and !found_after_remove and saw_type_change) {
        t.pass("§2.1.17");
    } else {
        t.fail("§2.1.17");
    }
    syscall.shutdown();
}
