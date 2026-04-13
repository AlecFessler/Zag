const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.17 — `DeviceRegionRights.irq` gates both `irq_ack` and meaningful use of the IRQ pending bit.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Find a device entry without IRQ rights and verify irq_ack returns E_PERM.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const rights: perms.DeviceRegionRights = @bitCast(@as(u8, @truncate(e.rights)));
        if (!rights.irq) {
            const rc = syscall.irq_ack(e.handle);
            t.expectEqual("§2.4.17", syscall.E_PERM, rc);
            syscall.shutdown();
        }
    }
    // All device entries have IRQ rights or none found — verify bogus handle returns E_BADHANDLE.
    const rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§2.4.17", syscall.E_BADHANDLE, rc);
    syscall.shutdown();
}
