const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const ROUNDS: u64 = 64;
const PAGES_PER_ROUND: u64 = 32;

/// §2.3.11 — revoking a VM reservation frees all pages in the range and clears the perm slot.
/// clears the perm slot.
///
/// We prove pages are actually returned to the kernel's physical page
/// allocator by repeatedly reserving a large region, faulting every page in,
/// then revoking — many times. If the kernel leaked the pages, by round N
/// the system would be out of memory and mem_reserve (or the first write)
/// would fail. We also verify that after each revoke the slot is clear and
/// the demand-paged replacement is zeroed (no stale data).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const region_size: u64 = PAGE * PAGES_PER_ROUND;

    var round: u64 = 0;
    while (round < ROUNDS) : (round += 1) {
        const result = syscall.mem_reserve(0, region_size, rw.bits());
        if (result.val < 0) {
            t.fail("§2.3.11");
            syscall.shutdown();
        }
        const handle: u64 = @bitCast(result.val);
        const base = result.val2;

        // Touch every page to force allocation of physical backing.
        var p: u64 = 0;
        while (p < PAGES_PER_ROUND) : (p += 1) {
            const ptr: *volatile u64 = @ptrFromInt(base + p * PAGE);
            ptr.* = 0xDEAD_BEEF_0000_0000 + round * PAGES_PER_ROUND + p;
        }

        // Revoke — pages should be freed back to the kernel allocator.
        if (syscall.revoke_perm(handle) != 0) {
            t.fail("§2.3.11");
            syscall.shutdown();
        }

        // Slot must be cleared.
        var slot_found = false;
        for (0..128) |i| {
            if (view[i].handle == handle and view[i].entry_type != perm_view.ENTRY_TYPE_EMPTY) {
                slot_found = true;
                break;
            }
        }
        if (slot_found) {
            t.fail("§2.3.11");
            syscall.shutdown();
        }
    }

    // After many rounds: if pages were leaked, we would be out of memory by
    // now. As a final check, make one more reservation of the same size and
    // verify we can still write every page AND that the demand-paged pages
    // are zeroed (no stale data survived).
    const final = syscall.mem_reserve(0, region_size, rw.bits());
    if (final.val < 0) {
        t.fail("§2.3.11");
        syscall.shutdown();
    }
    var p2: u64 = 0;
    while (p2 < PAGES_PER_ROUND) : (p2 += 1) {
        const ptr: *volatile u64 = @ptrFromInt(final.val2 + p2 * PAGE);
        if (ptr.* != 0) {
            t.fail("§2.3.11");
            syscall.shutdown();
        }
        ptr.* = 0x12345;
        if (ptr.* != 0x12345) {
            t.fail("§2.3.11");
            syscall.shutdown();
        }
    }
    t.pass("§2.3.11");
    syscall.shutdown();
}
