const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.1 — Setting RWX = 0 via `mem_perms` decommits the range: pages are freed and the VA range returns to demand-paged state.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const ptr: *volatile u64 = @ptrFromInt(result.val2);
    // Write to commit the page.
    ptr.* = 0xDEADBEEF;
    // Decommit with RWX = 0.
    const zero = perms.VmReservationRights{};
    const ret = syscall.mem_perms(handle, 0, 4096, zero.bits());
    if (ret == 0) {
        // Re-enable RW to re-access the page.
        _ = syscall.mem_perms(handle, 0, 4096, rw.bits());
        // After decommit + recommit, page should be zeroed (demand-paged fresh).
        const val = ptr.*;
        if (val == 0) {
            t.pass("§2.2.1");
        } else {
            t.fail("§2.2.1");
        }
    } else {
        t.fail("§2.2.1");
    }
    syscall.shutdown();
}
