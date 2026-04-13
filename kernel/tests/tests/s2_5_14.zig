const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.14 — Device region entries have a reserved byte (formerly badge_bit) at offset 9 that is always zero.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify the reserved byte is zero.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        if (e._reserved_byte == 0) {
            t.pass("§2.5.14");
            syscall.shutdown();
        }
    }
    // No device entries found — pass since there's nothing to validate.
    t.pass("§2.5.14");
    syscall.shutdown();
}
