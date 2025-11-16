const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const exceptions = zag.arch.x64.exceptions;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const gdt = zag.arch.x64.gdt;
const sched = zag.sched.scheduler;

const GateType = zag.arch.x64.idt.GateType;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const SchedInterruptContext = zag.sched.scheduler.SchedInterruptContext;

const NUM_IRQ_ENTRIES = 16;

var spurious_interrupts: u64 = 0;

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
}

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
