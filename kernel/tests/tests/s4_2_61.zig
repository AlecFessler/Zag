/// §4.2.61 — `vm_ioapic_assert_irq` with an invalid VM handle returns `E_BADHANDLE`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // No vm_create — pass a bogus handle.
    const result = syscall.vm_ioapic_assert_irq(0xDEAD, 0);
    t.expectEqual("§4.2.61", syscall.E_BADHANDLE, result);
    syscall.shutdown();
}
