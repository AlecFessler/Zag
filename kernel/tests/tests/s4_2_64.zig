/// §4.2.64 — `vm_ioapic_deassert_irq` with an invalid VM handle returns `E_BADCAP`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    // No vm_create — pass a bogus handle.
    const result = syscall.vm_ioapic_deassert_irq(0xDEAD, 0);
    t.expectEqual("§4.2.64", syscall.E_BADHANDLE, result);
    syscall.shutdown();
}
