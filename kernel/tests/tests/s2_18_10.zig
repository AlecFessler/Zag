const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.18.10 — The typical driver flow is: `notify_wait` to sleep until an IRQ fires, handle the interrupt in userspace, call `irq_ack` to unmask the line and allow future interrupts.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Verify the driver flow syscalls are callable in sequence:
    // 1. notify_wait(0) returns E_AGAIN (no pending IRQs)
    // 2. irq_ack with bogus handle returns E_BADHANDLE (confirming path exists)
    const wait_rc = syscall.notify_wait(0);
    const ack_rc = syscall.irq_ack(t.BOGUS_HANDLE);
    if (wait_rc == syscall.E_AGAIN and ack_rc == syscall.E_BADHANDLE) {
        t.pass("§2.18.10");
    } else {
        t.fail("§2.18.10");
    }
    syscall.shutdown();
}
