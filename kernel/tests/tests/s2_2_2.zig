const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.2 — Pages demand-paged after decommit are guaranteed to be zeroed.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const ptr: [*]volatile u8 = @ptrFromInt(result.val2);
    // Write non-zero data to commit the page.
    for (0..4096) |i| ptr[i] = 0xAA;
    // Decommit.
    _ = syscall.mem_perms(handle, 0, 4096, (perms.VmReservationRights{}).bits());
    // Recommit.
    _ = syscall.mem_perms(handle, 0, 4096, rw.bits());
    // Verify all zeroed.
    var all_zero = true;
    for (0..4096) |i| {
        if (ptr[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        t.pass("§2.2.2");
    } else {
        t.fail("§2.2.2");
    }
    syscall.shutdown();
}
