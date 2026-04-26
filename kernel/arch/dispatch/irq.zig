const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const DeviceRegion = zag.devices.device_region.DeviceRegion;

/// Bind a hardware IRQ source (LAPIC vector / GIC SPI) to a device_region
/// so subsequent firings increment its `irq_count` and futex-wake every
/// domain-local copy. Spec §[device_irq].
pub fn registerDeviceIrq(device: *DeviceRegion, irq_source: u32) !void {
    _ = device;
    _ = irq_source;
    return error.NotImplemented;
}

/// Tear down the binding installed by `registerDeviceIrq`. Subsequent
/// firings of the source are dropped.
pub fn unregisterDeviceIrq(device: *DeviceRegion) void {
    _ = device;
}

/// Mask an IRQ line at the interrupt controller. x86: I/O APIC redirection
/// table mask bit. aarch64: GICD_ICENABLER.
pub fn maskIrq(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.maskIrq(irq_line),
        .aarch64 => @panic("not implemented"),
        else => unreachable,
    }
}

/// Unmask an IRQ line at the interrupt controller. x86: clear I/O APIC
/// redirection table mask. aarch64: GICD_ISENABLER.
pub fn unmaskIrq(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unmaskIrq(irq_line),
        .aarch64 => aarch64.irq.unmaskIrq(irq_line),
        else => unreachable,
    }
}

/// Signal end-of-interrupt to the interrupt controller. x86: APIC EOI
/// (writes the EOI register; vector implicit). aarch64: ICC_EOIR1_EL1
/// keyed on the GIC INTID derived from `irq_line`.
pub fn endOfInterrupt(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        // x86 LAPIC EOI register is implicit on the in-service vector;
        // `irq_line` is unused on this branch.
        .x86_64 => x64.apic.endOfInterrupt(),
        .aarch64 => aarch64.gic.endOfInterrupt(@as(u32, irq_line) + 32),
        else => unreachable,
    }
}

/// Hardware IRQ entry — invoked from the per-arch ISR with the IRQ
/// source identifier. Routes to the bound device_region's `onIrq`
/// (increment counter, mask, propagate, futex-wake). Spec §[device_irq].
pub fn deviceIrqDispatch(irq_source: u32) void {
    _ = irq_source;
}
