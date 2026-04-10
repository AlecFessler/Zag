const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const N_PAGES: u64 = 4;

/// §3.4 — Demand-paged private region: allocate zeroed page, map, resume.
///
/// Reserves a multi-page region and writes a distinct sentinel into each
/// page to force separate demand faults. Then reads each back to confirm
/// all pages were mapped with their sentinel preserved (distinct backing
/// pages — not aliasing a single page) AND the initial read was zero
/// (zero-fill guarantee).
pub fn main(_: u64) void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, PAGE * N_PAGES, rights);
    if (result.val < 0) {
        t.fail("§3.4 vm_reserve");
        syscall.shutdown();
    }

    // First, verify each page reads as zero (zero-fill on demand).
    var p: u64 = 0;
    while (p < N_PAGES) : (p += 1) {
        const ptr: *volatile u64 = @ptrFromInt(result.val2 + p * PAGE);
        if (ptr.* != 0) {
            t.fail("§3.4 non-zero demand page");
            syscall.shutdown();
        }
    }

    // Write a distinct sentinel to each page's first u64.
    p = 0;
    while (p < N_PAGES) : (p += 1) {
        const ptr: *volatile u64 = @ptrFromInt(result.val2 + p * PAGE);
        ptr.* = 0xABCD_0000 + p;
    }

    // Read back — each sentinel must survive distinctly.
    p = 0;
    while (p < N_PAGES) : (p += 1) {
        const ptr: *volatile u64 = @ptrFromInt(result.val2 + p * PAGE);
        if (ptr.* != 0xABCD_0000 + p) {
            t.failWithVal("§3.4 sentinel mismatch", @bitCast(0xABCD_0000 + p), @bitCast(ptr.*));
            syscall.shutdown();
        }
    }

    t.pass("§3.4");
    syscall.shutdown();
}
