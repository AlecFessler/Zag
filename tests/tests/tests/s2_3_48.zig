const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.3.48 — Private nodes may be partially unmapped; the VMM split logic handles boundary splitting.
///
/// We reserve a 4-page region, commit all pages, then unmap pages 1-2 (the
/// middle two). Pages 0 and 3 must retain their data. The unmapped pages must
/// read back as zero (fresh demand-paged).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.mem_reserve(0, 4 * 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const base: u64 = vm.val2;

    // Write distinct patterns to each page.
    const p0: *volatile u64 = @ptrFromInt(base);
    const p1: *volatile u64 = @ptrFromInt(base + 4096);
    const p2: *volatile u64 = @ptrFromInt(base + 2 * 4096);
    const p3: *volatile u64 = @ptrFromInt(base + 3 * 4096);
    p0.* = 0x1111_1111_1111_1111;
    p1.* = 0x2222_2222_2222_2222;
    p2.* = 0x3333_3333_3333_3333;
    p3.* = 0x4444_4444_4444_4444;

    // Unmap pages 1-2 (middle two).
    const ret = syscall.mem_unmap(vm_handle, 4096, 2 * 4096);
    if (ret != 0) {
        t.failWithVal("§2.3.48 unmap", 0, ret);
        syscall.shutdown();
    }

    // Page 0 must retain data.
    if (p0.* != 0x1111_1111_1111_1111) {
        t.fail("§2.3.48 page0");
        syscall.shutdown();
    }

    // Pages 1-2 must be zeroed.
    if (p1.* != 0) {
        t.fail("§2.3.48 page1 not zeroed");
        syscall.shutdown();
    }
    if (p2.* != 0) {
        t.fail("§2.3.48 page2 not zeroed");
        syscall.shutdown();
    }

    // Page 3 must retain data.
    if (p3.* != 0x4444_4444_4444_4444) {
        t.fail("§2.3.48 page3");
        syscall.shutdown();
    }

    t.pass("§2.3.48");
    syscall.shutdown();
}
