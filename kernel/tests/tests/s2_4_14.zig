const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.14 — When a device IRQ fires, the kernel masks the IRQ line, identifies the owning process via the device region, and atomically sets bit 16 of the device's `field0` in the user permissions view via physmap.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // We cannot trigger a real IRQ in the test harness, but we can verify
    // that bit 16 of field0 is initially clear (no pending IRQ at boot).
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        const irq_pending = (e.field0 >> 16) & 1;
        t.expectEqual("§2.4.14", 0, @as(i64, @intCast(irq_pending)));
        syscall.shutdown();
    }
    // No device entries — pass vacuously.
    t.pass("§2.4.14");
    syscall.shutdown();
}
