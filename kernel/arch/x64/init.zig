const zag = @import("zag");

const exceptions = zag.arch.x64.exceptions;
const idt = zag.arch.x64.idt;
const irq = zag.arch.x64.irq;
const gdt = zag.arch.x64.gdt;
const serial = zag.arch.x64.serial;

pub fn init() void {
    serial.init(.com1, 115200);
    serial.print("Booting Zag x64 kernel...\n", .{});

    gdt.init();
    idt.init();
    exceptions.init();
    irq.init();
}
