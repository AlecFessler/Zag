const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

/// Mask an IRQ line at the interrupt controller. x86: I/O APIC redirection
/// table mask bit. aarch64: GICD_ICENABLER keyed on the GIC INTID derived
/// from `irq_line` (SPI base 32).
pub fn maskIrq(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.maskIrq(irq_line),
        .aarch64 => aarch64.gic.maskIrq(@as(u32, irq_line) + 32),
        else => unreachable,
    }
}

/// Unmask an IRQ line at the interrupt controller. x86: clear I/O APIC
/// redirection table mask. aarch64: GICD_ISENABLER keyed on the GIC INTID
/// derived from `irq_line` (SPI base 32).
pub fn unmaskIrq(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unmaskIrq(irq_line),
        .aarch64 => aarch64.gic.unmaskIrq(@as(u32, irq_line) + 32),
        else => unreachable,
    }
}

/// Signal end-of-interrupt to the interrupt controller. x86: APIC EOI
/// (writes the EOI register; vector implicit). aarch64: ICC_EOIR1_EL1
/// keyed on the GIC INTID derived from `irq_line` (SPI base 32).
pub fn endOfInterrupt(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        // x86 LAPIC EOI register is implicit on the in-service vector;
        // `irq_line` is unused on this branch.
        .x86_64 => x64.apic.endOfInterrupt(),
        .aarch64 => aarch64.gic.endOfInterrupt(@as(u32, irq_line) + 32),
        else => unreachable,
    }
}

