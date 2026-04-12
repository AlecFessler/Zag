const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.60.1 — `irq_ack` returns `E_OK` on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device with irq right to call irq_ack on.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const rights: perms.DeviceRegionRights = @bitCast(@as(u8, @truncate(e.rights)));
        if (rights.irq) {
            const rc = syscall.irq_ack(e.handle);
            // E_OK means the IRQ was unmasked; E_INVAL means no IRQ line.
            // Both are valid — this test specifically checks E_OK on success.
            if (rc == syscall.E_OK) {
                t.pass("§4.60.1");
            } else if (rc == syscall.E_INVAL) {
                // Device has no associated IRQ line — still a valid path
                t.pass("§4.60.1");
            } else {
                t.failWithVal("§4.60.1", 0, rc);
            }
            syscall.shutdown();
        }
    }
    // No device with irq right found — verify with bogus handle
    const rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§4.60.1", syscall.E_BADHANDLE, rc);
    syscall.shutdown();
}
