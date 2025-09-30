const std = @import("std");

const idt = @import("idt.zig");
const isr = @import("isr.zig");
const interrupts = @import("interrupts.zig");

const NUM_IRQ_ENTRIES = 16;

const IrqHandler = fn (*interrupts.InterruptContext) void;

var irq_handlers: [NUM_IRQ_ENTRIES]?IrqHandler = .{null} ** NUM_IRQ_ENTRIES;

export fn isrDispatcher(ctx: *interrupts.InterruptContext) void {
    // implement this once the pic driver is implemented
    _ = ctx;
    @panic("IRQ Dispatcher not yet implemented!\n");
}

pub fn registerIrq(irq_num: u4, handler: IrqHandler) void {
    if (irq_handlers[irq_num]) |_| {
        @panic("IRQ handler already registered!\n");
    } else {
        irq_handlers[irq_num] = handler;
        // clear pic mask when implemented
    }
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
