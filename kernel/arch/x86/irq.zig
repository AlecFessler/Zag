//! IRQ registration and gate setup.
//!
//! Provides a tiny registry for level-triggered IRQ lines and installs the
//! corresponding IDT gates after the CPU exception vectors. Dispatch is a
//! stub for now and will panic until implemented.

const interrupts = @import("interrupts.zig");
const idt = @import("idt.zig");
const isr = @import("isr.zig");
const std = @import("std");

/// Handler signature for hardware IRQs.
///
/// Receives a pointer to the interrupt context captured by the common stub.
/// Handlers should acknowledge/EOI the source before returning (once PIC/APIC
/// routing is wired up).
const IrqHandler = fn (*interrupts.InterruptContext) void;

/// Architectural IRQ lines exposed through the legacy PIC/APIC shim.
const NUM_IRQ_ENTRIES = 16;

/// Optional handler table indexed by IRQ number (0..15).
var irq_handlers: [NUM_IRQ_ENTRIES]?IrqHandler = .{null} ** NUM_IRQ_ENTRIES;

/// Top-level IRQ dispatcher (placeholder).
///
/// Arguments:
/// - `ctx`: interrupt context from the common stub
///
/// Currently unimplemented and will panic. Once wired, this will translate
/// the vector to an IRQ number, invoke the registered handler if any, and
/// signal EOI to the controller.
pub fn dispatchIrq(ctx: *interrupts.InterruptContext) void {
    _ = ctx;
    @panic("IRQ Dispatcher not yet implemented!\n");
}

/// Installs IDT gates for IRQ vectors.
///
/// Gates are opened at `isr.NUM_ISR_ENTRIES + irq` with kernel privilege,
/// using the generated naked stubs that conform to our `InterruptContext`
/// stack layout.
pub fn init() void {
    const offset = isr.NUM_ISR_ENTRIES;
    for (offset..offset + NUM_IRQ_ENTRIES) |i| {
        const int_stub = interrupts.getInterruptStub(i, false);
        idt.openInterruptGate(
            i,
            int_stub,
            0x08,
            idt.PrivilegeLevel.ring_0,
            idt.GateType.interrupt_gate,
        );
    }
}

/// Registers a handler for `irq_num` (0..15).
///
/// Panics if a handler is already present.
///
/// Arguments:
/// - `irq_num`: hardware IRQ index (0..15)
/// - `handler`: function pointer invoked by the dispatcher
pub fn registerIrq(irq_num: u4, handler: IrqHandler) void {
    if (irq_handlers[irq_num]) |_| {
        @panic("IRQ handler already registered!\n");
    } else {
        irq_handlers[irq_num] = handler;
    }
}
