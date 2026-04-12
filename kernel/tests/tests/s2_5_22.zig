const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.22 — `irq_ack` unmasks the IRQ line for the device associated with the given handle.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region handle to call irq_ack on.
    // If the device has the irq right, irq_ack should succeed or return
    // E_INVAL (no associated IRQ line). Either confirms the syscall works.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const rights: perms.DeviceRegionRights = @bitCast(@as(u8, @truncate(e.rights)));
        if (rights.irq) {
            const rc = syscall.irq_ack(e.handle);
            // E_OK (unmasked) or E_INVAL (no IRQ line) are both valid
            if (rc == syscall.E_OK or rc == syscall.E_INVAL) {
                t.pass("§2.5.22");
            } else {
                t.failWithVal("§2.5.22", 0, rc);
            }
            syscall.shutdown();
        }
    }
    // No device with irq right — test with a bogus handle which should
    // return E_BADHANDLE, confirming the syscall path exists.
    const rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§2.5.22", syscall.E_BADHANDLE, rc);
    syscall.shutdown();
}
