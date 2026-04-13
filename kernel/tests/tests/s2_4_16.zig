const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.16 — `irq_ack` atomically clears bit 16 of the device's `field0` in the user permissions view via physmap.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device with IRQ rights and call irq_ack; verify bit 16 stays clear.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const rights: perms.DeviceRegionRights = @bitCast(@as(u8, @truncate(e.rights)));
        if (rights.irq) {
            // Call irq_ack — should succeed or return E_INVAL (no IRQ line).
            const rc = syscall.irq_ack(e.handle);
            if (rc == syscall.E_OK or rc == syscall.E_INVAL) {
                // Verify bit 16 is clear after ack.
                const irq_pending = (e.field0 >> 16) & 1;
                t.expectEqual("§2.4.16", 0, @as(i64, @intCast(irq_pending)));
                syscall.shutdown();
            }
        }
    }
    // No device with IRQ right — verify irq_ack with bogus handle returns E_BADHANDLE.
    const rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§2.4.16", syscall.E_BADHANDLE, rc);
    syscall.shutdown();
}
