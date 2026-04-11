const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.20.1 — `revoke_perm` returns `E_OK` on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);

    // Verify it exists in perm_view before revoke.
    var found_before = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            found_before = true;
            break;
        }
    }

    const ret = syscall.revoke_perm(handle);

    // Verify it's gone from perm_view after revoke.
    var found_after = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            found_after = true;
            break;
        }
    }

    if (ret == 0 and found_before and !found_after) {
        t.pass("§4.20.1");
    } else {
        t.fail("§4.20.1");
    }
    syscall.shutdown();
}
