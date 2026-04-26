const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const device_region = zag.devices.device_region;
const x64 = zag.arch.x64;

const DeviceRegion = zag.devices.device_region.DeviceRegion;

/// Bind a hardware IRQ source (LAPIC vector / GIC SPI) to a device_region
/// so subsequent firings increment its `irq_count` and futex-wake every
/// domain-local copy. Spec §[device_irq].
pub fn registerDeviceIrq(device: *DeviceRegion, irq_source: u32) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.irq.registerDeviceIrq(device, irq_source),
        .aarch64 => try aarch64.gic.registerDeviceIrq(device, irq_source),
        else => unreachable,
    }
}

/// Tear down the binding installed by `registerDeviceIrq`. Subsequent
/// firings of the source are dropped.
pub fn unregisterDeviceIrq(device: *DeviceRegion) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unregisterDeviceIrq(device),
        .aarch64 => aarch64.gic.unregisterDeviceIrq(device),
        else => unreachable,
    }
}

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

/// Hardware IRQ entry — invoked from the per-arch ISR with the IRQ
/// source identifier. Resolves the bound device_region and delegates
/// to its `onIrq` handler (increment counter, mask, propagate, futex-wake).
/// Drops firings whose source has no current binding so a torn-down
/// device_region cannot resurrect itself through a stale ISR. Spec §[device_irq].
pub fn deviceIrqDispatch(irq_source: u32) void {
    if (device_region.findDeviceByIrqSource(irq_source) == null) return;
    device_region.onIrq(irq_source);
}
