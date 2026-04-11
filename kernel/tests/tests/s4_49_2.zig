/// §4.49.2 — `vm_ioapic_deassert_irq` with no VM returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // No vm_create — calling process has no VM.
    const result = syscall.vm_ioapic_deassert_irq(0);
    t.expectEqual("§4.49.2", syscall.E_INVAL, result);
    syscall.shutdown();
}
