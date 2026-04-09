const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.9.4 — At boot, the kernel inserts all device handles into the root service's permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Root should have at least one device handle at boot (QEMU q35 has PCI devices).
    var device_count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            device_count += 1;
        }
    }

    if (device_count > 0) {
        t.pass("§2.9.4");
    } else {
        t.fail("§2.9.4");
    }
    syscall.shutdown();
}
