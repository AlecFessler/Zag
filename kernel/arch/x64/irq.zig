const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const exceptions = zag.arch.x64.exceptions;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const paging_mod = zag.arch.x64.paging;
const sched = zag.sched.scheduler;

const GateType = zag.arch.x64.idt.GateType;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const SchedInterruptContext = zag.sched.scheduler.SchedInterruptContext;

/// 16 IRQ lines (vectors 32-47) — legacy ISA IRQs remapped above the 32 exception
/// vectors reserved by the architecture.
/// Intel SDM Vol 3A, §7.2 "Exception and Interrupt Vectors", Table 7-1 — vectors
/// 0-31 are reserved for exceptions; external device interrupts start at vector 32.
const NUM_IRQ_ENTRIES = 16;

var spurious_interrupts: u64 = 0;

/// Sets up IDT gates for hardware IRQs, the spurious interrupt vector, the TLB
/// shootdown IPI vector, and the scheduler timer vector.
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

    // Intel SDM Vol 3A, §13.9 "Spurious Interrupt" — the spurious-interrupt vector
    // register (SVR) at FEE0_00F0H specifies the vector delivered when the APIC
    // generates a spurious interrupt. Default after reset is 0xFF. The handler must
    // NOT send an EOI (spurious delivery does not set ISR).
    const spurious_int_vec = @intFromEnum(interrupts.IntVecs.spurious);
    idt.openInterruptGate(
        @intCast(spurious_int_vec),
        interrupts.STUBS[spurious_int_vec],
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
        interrupts.STUBS[tlb_vec],
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
        interrupts.STUBS[sched_int_vec],
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

