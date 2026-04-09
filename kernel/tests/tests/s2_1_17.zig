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
    const result = syscall.vm_reserve(0, 4096, rw.bits());
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
    if (found_after_insert and !found_after_remove) {
        t.pass("§2.1.17");
    } else {
        t.fail("§2.1.17");
    }
    syscall.shutdown();
}
