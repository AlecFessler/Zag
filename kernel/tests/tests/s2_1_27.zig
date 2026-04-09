const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.27 — `vm_reservation` entry: `field0` = start VAddr, `field1` = original size.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const size: u64 = 8192;
    const result = syscall.vm_reserve(0, size, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const vaddr = result.val2;
    // Find the entry in the user view.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            if (view[i].field0 == vaddr and view[i].field1 == size) {
                found = true;
            }
            break;
        }
    }
    if (found) {
        t.pass("§2.1.27");
    } else {
        t.fail("§2.1.27");
    }
    syscall.shutdown();
}
