const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const DeviceRegion = zag.memory.device_region.DeviceRegion;

pub fn enableInterrupts() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.enableInterrupts(),
        .aarch64 => aarch64.cpu.enableInterrupts(),
        else => unreachable,
    }
}

pub fn saveAndDisableInterrupts() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.saveAndDisableInterrupts(),
        .aarch64 => aarch64.cpu.saveAndDisableInterrupts(),
        else => unreachable,
    };
}

pub fn restoreInterrupts(state: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.restoreInterrupts(state),
        .aarch64 => aarch64.cpu.restoreInterrupts(state),
        else => unreachable,
    }
}

// --- IRQ notification (systems.md §irq-delivery) ---

pub fn maskIrq(irq: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.maskIrq(irq),
        .aarch64 => aarch64.irq.maskIrq(irq),
        else => unreachable,
    }
}

pub fn unmaskIrq(irq: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.unmaskIrq(irq),
        .aarch64 => aarch64.irq.unmaskIrq(irq),
        else => unreachable,
    }
}

pub fn findIrqForDevice(device: *DeviceRegion) ?u8 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.findIrqForDevice(device),
        .aarch64 => aarch64.irq.findIrqForDevice(device),
        else => unreachable,
    };
}

pub fn clearIrqPendingBit(irq_line: u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.clearIrqPendingBit(irq_line),
        .aarch64 => {}, // stub
        else => unreachable,
    }
}

pub fn registerIrqOwner(irq_line: u8, proc: *zag.proc.process.Process, slot_index: u16) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.irq.registerIrqOwner(irq_line, proc, slot_index),
        .aarch64 => {}, // stub
        else => unreachable,
    }
}

/// Temporarily allow kernel access to user pages.
/// x86: STAC (clear AC flag, disabling SMAP).
/// aarch64: clear PSTATE.PAN (disabling Privileged Access Never).
pub inline fn userAccessBegin() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.stac(),
        .aarch64 => aarch64.cpu.panDisable(),
        else => unreachable,
    }
}

/// Re-enable kernel protection from user page access.
/// x86: CLAC (set AC flag, enabling SMAP).
/// aarch64: set PSTATE.PAN (enabling Privileged Access Never).
pub inline fn userAccessEnd() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.clac(),
        .aarch64 => aarch64.cpu.panEnable(),
        else => unreachable,
    }
}
