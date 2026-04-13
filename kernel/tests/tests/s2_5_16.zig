const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.16 — Device region entries have a reserved byte at offset 9 that is always zero (badge_bit removed).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify the reserved byte is zero.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        if (e._reserved_byte == 0) {
            t.pass("§2.5.16");
            syscall.shutdown();
        }
    }
    t.fail("§2.5.16");
    syscall.shutdown();
}
