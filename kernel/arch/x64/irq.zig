const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const exceptions = zag.arch.x64.exceptions;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const paging_mod = zag.arch.x64.paging;
const sched = zag.sched.scheduler;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const GateType = zag.arch.x64.idt.GateType;
const PAddr = zag.memory.address.PAddr;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const SchedInterruptContext = zag.sched.scheduler.SchedInterruptContext;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;

/// 16 IRQ lines (vectors 32-47) — legacy ISA IRQs remapped above the 32 exception
/// vectors reserved by the architecture.
/// Intel SDM Vol 3A, §7.2 "Exception and Interrupt Vectors", Table 7-1 — vectors
/// 0-31 are reserved for exceptions; external device interrupts start at vector 32.
const num_irq_entries = 16;

var spurious_interrupts: u64 = 0;

/// Maps IRQ line numbers to the DeviceRegion that owns each line.
/// Populated during firmware table parsing. Static after boot.
/// Systems.md §24.
pub var irq_table: [256]?*DeviceRegion = [_]?*DeviceRegion{null} ** 256;

/// I/O APIC MMIO base virtual address. Set during ACPI parsing.
var ioapic_base: u64 = 0;
var ioapic_lock: SpinLock = .{};

/// Sets up IDT gates for hardware IRQs, the spurious interrupt vector, the TLB
/// shootdown IPI vector, and the scheduler timer vector.
pub fn init() void {
    const offset = exceptions.NUM_ISR_ENTRIES;
    for (offset..offset + num_irq_entries) |i| {
        idt.openInterruptGate(
            @intCast(i),
            interrupts.stubs[i],
            gdt.KERNEL_CODE_OFFSET,
            PrivilegeLevel.ring_0,
            GateType.interrupt_gate,
        );
    }

    // Intel SDM Vol 3A, §13.9 "Spurious Interrupt" — the spurious-interrupt vector
    // register (SVR) at FEE0_00F0H specifies the vector delivered when the APIC
    // generates a spurious interrupt. Default after reset is 0xFF. The handler must
    // NOT send an EOI (spurious delivery does not set ISR).
    const spurious_int_vec = @intFromEnum(interrupts.IntVecs.spurious);
    idt.openInterruptGate(
        @intCast(spurious_int_vec),
        interrupts.stubs[spurious_int_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        spurious_int_vec,
        spuriousHandler,
        .external,
    );

    const tlb_vec = @intFromEnum(interrupts.IntVecs.tlb_shootdown);
    idt.openInterruptGate(
        tlb_vec,
        interrupts.stubs[tlb_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        tlb_vec,
        paging_mod.tlbShootdownHandler,
        .external,
    );

    const sched_int_vec = @intFromEnum(interrupts.IntVecs.sched);
    idt.openInterruptGate(
        @intCast(sched_int_vec),
        interrupts.stubs[sched_int_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        sched_int_vec,
        schedTimerHandler,
        .external,
    );

    // SYSCALL/SYSRET replaces the old INT 0x80 path. The SYSCALL entry
    // point is set via MSR_LSTAR in cpu.initSyscall(); no IDT gate needed.
    // Intel SDM Vol 3A, §8.5.4 "SYSCALL and SYSENTER" — SYSCALL transfers
    // control without the IDT, using IA32_LSTAR for the entry point RIP.
}

/// Intel SDM Vol 3A, §13.9 — spurious interrupt handler must return without EOI
/// because the APIC does not set the ISR bit for spurious deliveries.
fn spuriousHandler(ctx: *cpu.Context) void {
    _ = ctx;
    spurious_interrupts += 1;
}

fn schedTimerHandler(ctx: *cpu.Context) void {
    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);
    const from_user = (ctx.cs & ring_3) == 3;

    var sched_interrupt_ctx: SchedInterruptContext = undefined;
    sched_interrupt_ctx.privilege = if (from_user) .user else .kernel;
    sched_interrupt_ctx.thread_ctx = @ptrCast(ctx);

    sched.schedTimerHandler(sched_interrupt_ctx);
}

/// Set the I/O APIC MMIO base address. Called during ACPI parsing.
pub fn setIoapicBase(phys_addr: u32) void {
    const phys = PAddr.fromInt(@as(u64, phys_addr));
    ioapic_base = VAddr.fromPAddr(phys, null).addr;
}

/// Mask an IRQ line by setting bit 16 (interrupt mask) of the low dword of
/// the I/O APIC redirection table entry for the given IRQ.
/// 82093AA I/O APIC Datasheet, §3.2.4 "I/O Redirection Table Registers" —
/// bit 16 of the low dword is the Interrupt Mask bit; 1 = masked.
/// Redirection table entry n occupies registers 0x10+2n (low) and 0x11+2n (high).
pub fn maskIrq(irq_line: u8) void {
    if (ioapic_base == 0) return;
    const reg = @as(u32, 0x10) + @as(u32, irq_line) * 2;
    const irq_state = ioapic_lock.lockIrqSave();
    const val = ioapicRead(reg);
    ioapicWrite(reg, val | (1 << 16));
    ioapic_lock.unlockIrqRestore(irq_state);
}

/// Unmask an IRQ line by clearing bit 16 (interrupt mask) of the low dword of
/// the I/O APIC redirection table entry for the given IRQ.
/// 82093AA I/O APIC Datasheet, §3.2.4 "I/O Redirection Table Registers" —
/// bit 16 of the low dword is the Interrupt Mask bit; 0 = unmasked.
pub fn unmaskIrq(irq_line: u8) void {
    if (ioapic_base == 0) return;
    const reg = @as(u32, 0x10) + @as(u32, irq_line) * 2;
    const irq_state = ioapic_lock.lockIrqSave();
    const val = ioapicRead(reg);
    ioapicWrite(reg, val & ~@as(u32, 1 << 16));
    ioapic_lock.unlockIrqRestore(irq_state);
}

/// Look up which IRQ line, if any, is assigned to the given device region.
pub fn findIrqForDevice(device: *DeviceRegion) ?u8 {
    for (irq_table, 0..) |dev_ptr, i| {
        if (dev_ptr == device) return @truncate(i);
    }
    return null;
}

/// Read a 32-bit register from the I/O APIC via the indirect MMIO interface.
/// 82093AA I/O APIC Datasheet, §3.1 "I/O APIC Registers" — IOREGSEL at
/// base+0x00 selects the register index; IOWIN at base+0x10 is the data window.
fn ioapicRead(reg: u32) u32 {
    const sel: *volatile u32 = @ptrFromInt(ioapic_base);
    const win: *const volatile u32 = @ptrFromInt(ioapic_base + 0x10);
    sel.* = reg;
    return win.*;
}

/// Write a 32-bit register to the I/O APIC via the indirect MMIO interface.
/// 82093AA I/O APIC Datasheet, §3.1 "I/O APIC Registers" — IOREGSEL at
/// base+0x00 selects the register index; IOWIN at base+0x10 is the data window.
fn ioapicWrite(reg: u32, val: u32) void {
    const sel: *volatile u32 = @ptrFromInt(ioapic_base);
    const win: *volatile u32 = @ptrFromInt(ioapic_base + 0x10);
    sel.* = reg;
    win.* = val;
}
