const interrupts = @import("interrupts.zig");
const idt = @import("idt.zig");
const isr = @import("isr.zig");
const std = @import("std");

const IrqHandler = fn (*interrupts.InterruptContext) void;

const NUM_IRQ_ENTRIES = 16;

var irq_handlers: [NUM_IRQ_ENTRIES]?IrqHandler = .{null} ** NUM_IRQ_ENTRIES;

pub fn dispatchIrq(ctx: *interrupts.InterruptContext) void {
    _ = ctx;
    @panic("IRQ Dispatcher not yet implemented!\n");
}

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

pub fn registerIrq(irq_num: u4, handler: IrqHandler) void {
    if (irq_handlers[irq_num]) |_| {
        @panic("IRQ handler already registered!\n");
    } else {
        irq_handlers[irq_num] = handler;
    }
}
