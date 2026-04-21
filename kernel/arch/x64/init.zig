const zag = @import("zag");

const acpi = zag.arch.x64.acpi;
const cpu = zag.arch.x64.cpu;
const exceptions = zag.arch.x64.exceptions;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const irq = zag.arch.x64.irq;
const serial = zag.arch.x64.serial;

const PAddr = zag.memory.address.PAddr;

pub fn init() void {
    serial.init(.com1, 115200);
    gdt.init();
    idt.init();
    exceptions.init();
    irq.init();
    cpu.initSyscall(@intFromPtr(&interrupts.syscallEntry));
    interrupts.initSyscallScratch(0);
    cpu.initPat();
    cpu.enableAlignmentCheck();
    cpu.enableSmapSmep();
    cpu.enablePcid();
    cpu.enableSpeculationBarriers();
}
