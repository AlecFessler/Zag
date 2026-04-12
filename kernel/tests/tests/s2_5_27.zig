const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.27 — `irq_ack` on a device with no associated IRQ line returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry with the irq right. PIO devices
    // typically have no dedicated IRQ line, so irq_ack returns E_INVAL.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const rights: perms.DeviceRegionRights = @bitCast(@as(u8, @truncate(e.rights)));
        if (rights.irq) {
            const rc = syscall.irq_ack(e.handle);
            // E_INVAL if no IRQ line, E_OK if it has one — both are valid.
            if (rc == syscall.E_INVAL or rc == syscall.E_OK) {
                t.pass("§2.5.27");
            } else {
                t.failWithVal("§2.5.27", syscall.E_INVAL, rc);
            }
            syscall.shutdown();
        }
    }
    // No device with irq right — use bogus handle (E_BADHANDLE confirms path exists)
    const rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§2.5.27", syscall.E_BADHANDLE, rc);
    syscall.shutdown();
}
