const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.8 — Private nodes may be partially unmapped — the VMM split logic handles boundary splitting as it does for `mem_perms`.
///
/// We reserve a 3-page region, commit all pages by writing to them, then unmap
/// only the middle page. The first and last pages must retain their data while
/// the middle page reverts to zeroed demand-paged memory.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 3 * 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const base: u64 = vm.val2;

    // Commit all three pages with distinct patterns.
    const p0: *volatile u64 = @ptrFromInt(base);
    const p1: *volatile u64 = @ptrFromInt(base + 4096);
    const p2: *volatile u64 = @ptrFromInt(base + 2 * 4096);
    p0.* = 0xAAAA_AAAA_AAAA_AAAA;
    p1.* = 0xBBBB_BBBB_BBBB_BBBB;
    p2.* = 0xCCCC_CCCC_CCCC_CCCC;

    // Unmap only the middle page (partial unmap of a private range).
    const ret = syscall.mem_unmap(vm_handle, 4096, 4096);
    if (ret != 0) {
        t.failWithVal("§2.3.8 unmap", 0, ret);
        syscall.shutdown();
    }

    // First page must retain its data.
    if (p0.* != 0xAAAA_AAAA_AAAA_AAAA) {
        t.fail("§2.3.8 page0 corrupted");
        syscall.shutdown();
    }

    // Middle page must be zeroed (demand-paged fresh).
    if (p1.* != 0) {
        t.fail("§2.3.8 middle page not zeroed");
        syscall.shutdown();
    }

    // Last page must retain its data.
    if (p2.* != 0xCCCC_CCCC_CCCC_CCCC) {
        t.fail("§2.3.8 page2 corrupted");
        syscall.shutdown();
    }

    t.pass("§2.3.8");
    syscall.shutdown();
}
