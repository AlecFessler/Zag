//! IRQ registration and gate setup.
//!
//! Provides a tiny registry for level-triggered IRQ lines and installs the
//! corresponding IDT gates after the CPU exception vectors. A spurious-IRQ
//! software handler is registered and tracked via a simple counter.
//!
//! # Directory
//!
//! ## Type Definitions
//! - None.
//!
//! ## Constants
//! - `NUM_IRQ_ENTRIES` – number of legacy IRQ lines exposed by PIC/APIC shim.
//!
//! ## Variables
//! - `spurious_interrupts` – global counter of spurious interrupts observed.
//!
//! ## Functions
//! - `init` – install IRQ IDT gates and register software/LAPIC handlers.
//! - `spuriousHandler` – increment the spurious interrupt counter (private).

const cpu = @import("cpu.zig");
const exceptions = @import("exceptions.zig");
const idt = @import("idt.zig");
const interrupts = @import("interrupts.zig");
const serial = @import("serial.zig");
const std = @import("std");
const zag = @import("zag");

const sched = zag.sched.scheduler;
const ps2_keyboard = zag.drivers.ps2_keyboard;

/// Number of legacy IRQ lines exposed by the PIC/APIC shim.
const NUM_IRQ_ENTRIES = 16;

/// Global counter of spurious interrupts observed.
var spurious_interrupts: u64 = 0;

/// Summary:
/// Installs IDT gates for legacy IRQ vectors and registers the spurious and
/// scheduler handlers with the interrupt dispatcher.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - void.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Software handler for spurious interrupts; increments the global counter.
///
/// Arguments:
/// - ctx: Pointer to the interrupt context captured by the common stub.
///
/// Returns:
/// - void.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn spuriousHandler(ctx: *cpu.Context) void {
    _ = ctx;
    spurious_interrupts += 1;
}
