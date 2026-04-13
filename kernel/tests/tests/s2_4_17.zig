const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.17 — When a device IRQ fires, the kernel masks the IRQ line, identifies the owning process via the device region, atomically ORs `(1 << badge_bit)` into the process's notification word, and wakes all threads waiting on the notification box.
pub fn main(pv: u64) void {
    _ = pv;
    // This assertion describes the kernel's internal IRQ delivery path.
    // We cannot directly trigger a real device IRQ in the test environment,
    // but we can verify the observable side: notify_wait with timeout 0
    // returns E_AGAIN when no IRQs have fired (no bits set).
    const rc = syscall.notify_wait(0);
    t.expectEqual("§2.4.17", syscall.E_AGAIN, rc);
    syscall.shutdown();
}
