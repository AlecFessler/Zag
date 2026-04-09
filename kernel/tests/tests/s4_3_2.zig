const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.3.2 — `vm_reserve` returns vaddr via second return register.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    if (result.val <= 0 or result.val2 == 0 or result.val2 % 4096 != 0) {
        t.fail("§4.3.2");
        syscall.shutdown();
    }

    // Verify the returned address is actually usable.
    const ptr: *volatile u64 = @ptrFromInt(result.val2);
    ptr.* = 0xDEAD_BEEF_CAFE_BABE;
    const readback = ptr.*;
    if (readback == 0xDEAD_BEEF_CAFE_BABE) {
        t.pass("§4.3.2");
    } else {
        t.fail("§4.3.2");
    }
    syscall.shutdown();
}
