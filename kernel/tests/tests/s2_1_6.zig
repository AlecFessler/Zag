const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.6 — A `dead_process` handle remains valid until explicitly revoked.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_exit.ptr), children.child_exit.len, child_rights.bits())));

    // Locate the child slot and wait for it to convert to dead_process.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    if (view[slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.fail("§2.1.6 child never became dead_process");
        syscall.shutdown();
    }

    // Persistence check: perform several intervening operations and verify
    // the dead_process slot survives them untouched.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const r1 = syscall.vm_reserve(0, 4096, rw.bits());
    const vm_handle: u64 = @bitCast(r1.val);
    const shm_rc = syscall.shm_create(4096);
    const shm_handle: u64 = @bitCast(shm_rc);
    for (0..10) |_| syscall.thread_yield();
    _ = syscall.revoke_perm(vm_handle);
    _ = syscall.revoke_perm(shm_handle);

    if (view[slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS or view[slot].handle != child_handle) {
        t.fail("§2.1.6 dead_process slot did not persist across unrelated ops");
        syscall.shutdown();
    }

    // Now explicitly revoke — the slot must become EMPTY.
    const rev = syscall.revoke_perm(child_handle);
    if (rev != 0) {
        t.failWithVal("§2.1.6 revoke_perm", 0, rev);
        syscall.shutdown();
    }
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_EMPTY) {
        t.pass("§2.1.6");
    } else {
        t.fail("§2.1.6 slot not EMPTY after revoke");
    }
    syscall.shutdown();
}
