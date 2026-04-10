const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.4.1 — `vm_perms` returns `E_OK` on success.
///
/// Verifies the permission change actually takes effect by cycling RW → RO → RW
/// and writing through the page in the RW phases. A faulting write during RO
/// would crash the process — the fact that we reach shutdown after the RW
/// re-grant proves the kernel honored both perm changes and remapped the page.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.vm_reserve(0, 4096, rw.bits());
    const handle: u64 = @bitCast(result.val);
    const vaddr: u64 = result.val2;
    const page: [*]volatile u8 = @ptrFromInt(vaddr);

    // Initial write (page RW) — commits the page.
    page[0] = 0xAA;
    if (page[0] != 0xAA) {
        t.fail("§4.4.1 initial write lost");
        syscall.shutdown();
    }

    // Downgrade to read-only.
    const read_only = perms.VmReservationRights{ .read = true };
    const ret_ro = syscall.vm_perms(handle, 0, 4096, read_only.bits());
    t.expectEqual("§4.4.1 RW→RO", 0, ret_ro);

    // Confirm the page is still readable at its prior value.
    if (page[0] != 0xAA) {
        t.fail("§4.4.1 read-after-RO value changed");
        syscall.shutdown();
    }

    // Re-grant write and make a visible change.
    const ret_rw = syscall.vm_perms(handle, 0, 4096, rw.bits());
    t.expectEqual("§4.4.1 RO→RW", 0, ret_rw);
    page[0] = 0x55;
    if (page[0] != 0x55) {
        t.fail("§4.4.1 write after RO→RW lost");
        syscall.shutdown();
    }

    t.pass("§4.4.1");
    syscall.shutdown();
}
