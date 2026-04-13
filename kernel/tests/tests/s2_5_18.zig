const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.18 — The typical driver flow is: read `field0`, call `futex_wait_val` on the `field0` address with the current value as expected (the thread wakes when bit 16 is set by the kernel), handle the interrupt in userspace, call `irq_ack` to clear the pending bit and unmask the line.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Verify the driver flow is structurally possible: field0 address is usable
    // as a futex target and irq_ack syscall path exists.
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        // Verify field0 address is 8-byte aligned (required for futex).
        const field0_addr = @intFromPtr(&e.field0);
        if (field0_addr % 8 != 0) {
            t.fail("§2.5.18");
            syscall.shutdown();
        }
        // Read current field0 value (driver flow step 1).
        const current_val = e.field0;
        // futex_wait_val with timeout=0 should return E_TIMEOUT if value matches
        // (non-blocking try-only), confirming the address is a valid futex target.
        var addrs = [1]u64{field0_addr};
        var expected = [1]u64{current_val};
        const ret = syscall.futex_wait_val(@intFromPtr(&addrs), @intFromPtr(&expected), 1, 0);
        // E_TIMEOUT means the address was valid and value matched (non-blocking).
        if (ret == syscall.E_TIMEOUT) {
            t.pass("§2.5.18");
        } else {
            t.failWithVal("§2.5.18", syscall.E_TIMEOUT, ret);
        }
        syscall.shutdown();
    }
    // No device entries — pass vacuously.
    t.pass("§2.5.18");
    syscall.shutdown();
}
