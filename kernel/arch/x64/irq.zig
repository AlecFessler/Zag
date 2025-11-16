const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const exceptions = zag.arch.x64.exceptions;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const gdt = zag.arch.x64.gdt;

const GateType = zag.arch.x64.idt.GateType;
const PrivilegeLevel = zag.arch.x64.idt.PrivilegeLevel;

const NUM_IRQ_ENTRIES = 16;

pub fn init() void {
    const offset = exceptions.NUM_ISR_ENTRIES;
    for (offset..offset + NUM_IRQ_ENTRIES) |i| {
        idt.openInterruptGate(
            @intCast(i),
            interrupts.STUBS[i],
            gdt.KERNEL_CODE_OFFSET,
            PrivilegeLevel.ring_0,
            GateType.interrupt_gate,
        );
    }
}
