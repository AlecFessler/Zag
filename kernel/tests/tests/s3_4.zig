const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.4 — Demand-paged private region: allocate zeroed page, map, resume.
pub fn main(_: u64) void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, 4096, rights);
    if (result.val < 0) {
        t.fail("§3.4");
        syscall.shutdown();
    }
    // Reading the demand-paged region should trigger a page fault,
    // the kernel allocates a zeroed page, maps it, and resumes us.
    const ptr: [*]const u8 = @ptrFromInt(result.val2);
    var all_zero = true;
    for (0..4096) |i| {
        if (ptr[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        t.pass("§3.4");
    } else {
        t.fail("§3.4");
    }
    syscall.shutdown();
}
