const std = @import("std");
const zag = @import("zag");

const cpu = zag.x86.Cpu;
const idt = zag.x86.Idt;
const apic = zag.x86.Apic;
const serial = zag.x86.Serial;
const paging = zag.x86.Paging;

const VAddr = paging.VAddr;

pub const KEYBOARD_IRQ_PIN: u8 = 1;

pub fn init(vector: u8) void {
    apic.ioapicRouteIrq(KEYBOARD_IRQ_PIN, vector);
}

pub fn keyboardIrqHandler(ctx: *cpu.Context) void {
    _ = ctx;

    const scancode: u8 = cpu.inb(0x60);
    serial.print("kbd scancode: 0x{X:02}\n", .{scancode});
}
