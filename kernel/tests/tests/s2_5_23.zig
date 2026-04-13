const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.23 — The typical driver IRQ flow uses futex_wait on the device's user view entry field0, handles the interrupt in userspace, and calls `irq_ack` to unmask the line.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Verify irq_ack with bogus handle returns E_BADHANDLE (confirming path exists).
    // notify_wait is removed; the new flow uses futex_wait on field0.
    const ack_rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§2.5.23", syscall.E_BADHANDLE, ack_rc);
    syscall.shutdown();
}
