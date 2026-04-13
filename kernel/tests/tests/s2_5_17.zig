const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.17 — When a device IRQ fires, the kernel masks the IRQ line, sets bit 16 of field0 in the device's user view entry, and wakes futex waiters on that address.
pub fn main(pv: u64) void {
    _ = pv;
    // The old notify_wait syscall is removed; verify it returns E_INVAL.
    const rc = syscall.notify_wait(0);
    t.expectEqual("§2.5.17", syscall.E_INVAL, rc);
    syscall.shutdown();
}
