const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.1.2 — SHM is freed when the last handle holder revokes or exits.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create SHM.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Verify it exists in perm_view.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == shm_h and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            found = true;
            break;
        }
    }

    // Revoke it — last holder, should be freed.
    const ret = syscall.revoke_perm(shm_h);

    // Verify slot is cleared.
    var still_exists = false;
    for (0..128) |i| {
        if (view[i].handle == shm_h and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            still_exists = true;
            break;
        }
    }

    if (found and ret == 0 and !still_exists) {
        t.pass("§3.1.2");
    } else {
        t.fail("§3.1.2");
    }
    syscall.shutdown();
}
