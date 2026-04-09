const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.11 — Revoking a VM reservation frees all pages in the range and clears the perm slot.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const addr = result.val2;
    // Write to the page to ensure it's faulted in.
    const ptr: *volatile u64 = @ptrFromInt(addr);
    ptr.* = 0xDEAD_BEEF;
    // Revoke the reservation.
    _ = syscall.revoke_perm(handle);
    // Verify the slot is cleared.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == handle and view[i].entry_type != perm_view.ENTRY_TYPE_EMPTY) {
            found = true;
            break;
        }
    }
    if (found) {
        t.fail("§2.3.11");
        syscall.shutdown();
    }
    // Reserve a new region at the same hint address. If old pages weren't freed,
    // the new demand-paged page should still be zeroed (not contain 0xDEAD_BEEF).
    const result2 = syscall.vm_reserve(addr, 4096, rw.bits());
    if (result2.val < 0) {
        t.fail("§2.3.11");
        syscall.shutdown();
    }
    const ptr2: *volatile u64 = @ptrFromInt(result2.val2);
    if (ptr2.* == 0) {
        t.pass("§2.3.11");
    } else {
        t.failWithVal("§2.3.11", 0, @bitCast(ptr2.*));
    }
    syscall.shutdown();
}
