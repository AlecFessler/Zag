//! IRQ registration and gate setup.
//!
//! Provides a tiny registry for level-triggered IRQ lines and installs the
//! corresponding IDT gates after the CPU exception vectors. Dispatch is a
//! stub for now and will panic until implemented.

const std = @import("std");

const cpu = @import("cpu.zig");
const exceptions = @import("exceptions.zig");
const interrupts = @import("interrupts.zig");
const idt = @import("idt.zig");
const serial = @import("serial.zig");

const zag = @import("zag");
const sched = zag.sched.scheduler;

/// Architectural IRQ lines exposed through the legacy PIC/APIC shim.
const NUM_IRQ_ENTRIES = 16;

var spurious_interrupts: u64 = 0;

/// Installs IDT gates for IRQ vectors.
///
/// Gates are opened at `isr.NUM_ISR_ENTRIES + irq` with kernel privilege,
/// using the generated naked stubs that conform to our `Context`
/// stack layout.
pub fn init() void {
    const offset = exceptions.NUM_ISR_ENTRIES;
    for (offset..offset + NUM_IRQ_ENTRIES) |i| {
        idt.openInterruptGate(
            @intCast(i),
            interrupts.STUBS[i],
            0x08,
            idt.PrivilegeLevel.ring_0,
            idt.GateType.interrupt_gate,
        );
    }

    const spurious_int_vec = @intFromEnum(idt.IntVectors.spurious);
    idt.openInterruptGate(
        @intCast(spurious_int_vec),
        interrupts.STUBS[spurious_int_vec],
        0x08,
        idt.PrivilegeLevel.ring_0,
        idt.GateType.interrupt_gate,
    );
    interrupts.registerSoftware(
        spurious_int_vec,
        spuriousHandler,
    );

    const sched_int_vec = @intFromEnum(idt.IntVectors.sched);
    idt.openInterruptGate(
        @intCast(sched_int_vec),
        interrupts.STUBS[sched_int_vec],
        0x08,
        idt.PrivilegeLevel.ring_0,
        idt.GateType.interrupt_gate,
    );
    interrupts.registerExternalLapic(
        sched_int_vec,
        sched.schedTimerHandler,
    );
}

fn spuriousHandler(ctx: *cpu.Context) void {
    _ = ctx;
    spurious_interrupts += 1;
}
