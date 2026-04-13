const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.15 — Device region entries expose device metadata via field0; the reserved byte (formerly badge_bit) is zero.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry and verify the reserved byte is zero.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        if (e._reserved_byte == 0) {
            t.pass("§2.5.15");
            syscall.shutdown();
        }
    }
    // No device entries found — this means the test rig has no devices,
    // which should not happen under QEMU q35.
    t.fail("§2.5.15");
    syscall.shutdown();
}
