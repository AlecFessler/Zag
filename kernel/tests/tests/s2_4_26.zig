const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.26 — `irq_ack` without `DeviceRegionRights.irq` on the device handle returns `E_PERM`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device region entry WITHOUT the irq right.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const rights: perms.DeviceRegionRights = @bitCast(@as(u8, @truncate(e.rights)));
        if (!rights.irq) {
            const rc = syscall.irq_ack(e.handle);
            t.expectEqual("§2.4.26", syscall.E_PERM, rc);
            syscall.shutdown();
        }
    }
    // All devices have irq right — try with a non-device handle (slot 0 = process).
    // This would return E_BADHANDLE, not E_PERM; we need a device without irq.
    // As a fallback, if all devices have irq, pass since the kernel would
    // correctly enforce E_PERM if one didn't.
    t.fail("§2.4.26");
    syscall.shutdown();
}
