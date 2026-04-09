const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.9.2 — Device user view `field0` encodes: `device_type(u8) | device_class(u8) << 8 | size_or_port_count(u32) << 32`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device and verify field0 encoding makes sense.
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            const dev_type = view[i].deviceType();
            const size = view[i].deviceSizeOrPortCount();
            // device_type must be 0 (MMIO) or 1 (port_io).
            if (dev_type <= 1 and size > 0) {
                t.pass("§2.9.2");
                syscall.shutdown();
            }
        }
    }
    t.fail("§2.9.2");
    syscall.shutdown();
}
