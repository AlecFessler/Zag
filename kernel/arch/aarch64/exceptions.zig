//! AArch64 exception vector table and ESR_EL1 decoding.
//!
//! ARM exceptions use a vector table pointed to by VBAR_EL1. The table has
//! 16 entries (4 groups x 4 exception types), each 0x80 bytes apart.
//! This replaces x86's IDT entirely.
//!
//! Vector table layout (ARM ARM D1.10.2, Table D1-7):
//!   Offset  Source              Type
//!   0x000   Current EL, SP0     Synchronous
//!   0x080   Current EL, SP0     IRQ
//!   0x100   Current EL, SP0     FIQ
//!   0x180   Current EL, SP0     SError
//!   0x200   Current EL, SPx     Synchronous
//!   0x280   Current EL, SPx     IRQ
//!   0x300   Current EL, SPx     FIQ
//!   0x380   Current EL, SPx     SError
//!   0x400   Lower EL, AArch64   Synchronous  <- syscalls, page faults from EL0
//!   0x480   Lower EL, AArch64   IRQ          <- device interrupts from EL0
//!   0x500   Lower EL, AArch64   FIQ
//!   0x580   Lower EL, AArch64   SError
//!   0x600   Lower EL, AArch32   Synchronous  (not used -- we don't run AArch32)
//!   ...
//!
//! ESR_EL1 (Exception Syndrome Register) decoding -- ARM ARM D13.2.37:
//!   Bits [31:26] = EC (Exception Class):
//!     0x15 = SVC from AArch64 (syscall)
//!     0x20 = Instruction Abort from lower EL
//!     0x21 = Instruction Abort from same EL
//!     0x24 = Data Abort from lower EL (page fault)
//!     0x25 = Data Abort from same EL
//!     0x00 = Unknown reason
//!
//!   For Data/Instruction Aborts, bits [5:0] = DFSC/IFSC (Fault Status Code):
//!     0b0001xx = Translation fault (level 0-3)
//!     0b0010xx = Access flag fault (level 0-3)
//!     0b0011xx = Permission fault (level 0-3)
//!
//! FAR_EL1 holds the faulting virtual address (equivalent of x86 CR2).
//!
//! References:
//! - ARM ARM D1.10: Exception vectors
//! - ARM ARM D13.2.37: ESR_EL1
//! - ARM ARM D13.2.40: FAR_EL1

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const gic = zag.arch.aarch64.gic;
const scheduler = zag.sched.scheduler;
const syscall_dispatch = zag.syscall.dispatch;

const ArchCpuContext = zag.arch.aarch64.interrupts.ArchCpuContext;
const FaultReason = zag.perms.permissions.FaultReason;
const PageFaultContext = zag.arch.aarch64.interrupts.PageFaultContext;

/// ARM ARM D13.2.37 -- ESR_EL1 Exception Class field, bits [31:26].
/// Identifies the reason for the exception that was taken to EL1.
const ExceptionClass = enum(u6) {
    unknown = 0x00,
    wf_trapped = 0x01,
    svc_aarch64 = 0x15,
    instruction_abort_lower_el = 0x20,
    instruction_abort_same_el = 0x21,
    pc_alignment = 0x22,
    data_abort_lower_el = 0x24,
    data_abort_same_el = 0x25,
    sp_alignment = 0x26,
    serror = 0x2f,
    breakpoint_lower_el = 0x30,
    breakpoint_same_el = 0x31,
    software_step_lower_el = 0x32,
    software_step_same_el = 0x33,
    watchpoint_lower_el = 0x34,
    watchpoint_same_el = 0x35,
    brk_instruction = 0x3c,
    _,
};

/// Extract the Exception Class from ESR_EL1 (bits [31:26]).
/// ARM ARM D13.2.37.
fn extractEc(esr: u64) ExceptionClass {
    return @enumFromInt(@as(u6, @truncate(esr >> 26)));
}

/// ARM ARM D13.2.37 -- For Data Aborts, bit 6 (WnR) indicates whether
/// the fault was caused by a write (1) or a read (0).
fn isWriteFault(esr: u64) bool {
    return (esr >> 6) & 1 == 1;
}

// ── Exception Vector Table ──────────────────────────────────────────────
//
// ARM ARM D1.10.2, Table D1-7: The vector table must be 2048-byte aligned.
// Each entry is 0x80 (128) bytes, containing actual code (not pointers).
// The hardware jumps directly to VBAR_EL1 + offset on exception.
//
// Each 0x80 entry has room for 32 instructions. The entry saves x0 and x30
// to the stack, loads the handler address into x0, and branches to a shared
// trampoline (exceptionTrampoline) that completes the register save, calls
// the handler, restores all registers, and executes ERET.
//
// Register save order matches ArchCpuContext layout:
//   x0-x30 (31 regs = 248 bytes), sp_el0 (8), elr_el1 (8), spsr_el1 (8)
//   Total: 272 bytes = 0x110

/// The exception vector table -- a single naked function whose code is laid
/// out as 16 entries of 0x80 bytes each. Each entry saves x0/x30, loads the
/// handler address, and branches to the shared trampoline.
///
/// ARM ARM D1.10.2, Table D1-7.
fn exceptionVectorTable() align(2048) callconv(.naked) void {
    // 0x000: Current EL SP0, Synchronous.
    //
    // This vector fires when an exception is taken at EL1 while
    // SPSel=0, i.e. the executing context was EL1t (kernel code
    // running on SP_EL0 rather than SP_EL1). Kernel threads created
    // by `vcpu.create` run at EL1t so their per-thread stack can be
    // restored via the normal SP_EL0 slot in ArchCpuContext — which
    // means their exceptions land here rather than at 0x200. Route
    // this to the same synchronous handler as Current EL SPx.
    asm volatile (
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_current]
        \\add x0, x0, :lo12:%[sync_current]
        \\b %[trampoline]

        // 0x080: Current EL SP0, IRQ — kernel-thread IRQ delivery.
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[irq_current]
        \\add x0, x0, :lo12:%[irq_current]
        \\b %[trampoline]

        // 0x100: Current EL SP0, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x180: Current EL SP0, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x200: Current EL SPx, Synchronous (kernel faults)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_current]
        \\add x0, x0, :lo12:%[sync_current]
        \\b %[trampoline]

        // 0x280: Current EL SPx, IRQ (kernel IRQ)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[irq_current]
        \\add x0, x0, :lo12:%[irq_current]
        \\b %[trampoline]

        // 0x300: Current EL SPx, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x380: Current EL SPx, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x400: Lower EL AArch64, Synchronous (syscalls, page faults)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_lower]
        \\add x0, x0, :lo12:%[sync_lower]
        \\b %[trampoline]

        // 0x480: Lower EL AArch64, IRQ (device interrupts from userspace)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[irq_lower]
        \\add x0, x0, :lo12:%[irq_lower]
        \\b %[trampoline]

        // 0x500: Lower EL AArch64, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x580: Lower EL AArch64, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x600: Lower EL AArch32, Synchronous (not supported)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x680: Lower EL AArch32, IRQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x700: Lower EL AArch32, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x780: Lower EL AArch32, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]
        :
        : [trampoline] "S" (&exceptionTrampoline),
          [unexpected] "S" (&handleUnexpected),
          [sync_current] "S" (&handleSyncCurrentEl),
          [irq_current] "S" (&handleIrqCurrentEl),
          [sync_lower] "S" (&handleSyncLowerEl),
          [irq_lower] "S" (&handleIrqLowerEl),
    );
}

/// Shared trampoline called from each vector entry.
///
/// Entry contract:
///   - x0 = address of the Zig handler function to call
///   - x30 and original x0 are saved at [sp] (pushed by the vector stub)
///   - sp points to the pre-push stack minus 16 bytes
///
/// This function completes the full ArchCpuContext save, calls the handler
/// with a pointer to the context, then restores all registers and ERETs.
fn exceptionTrampoline() callconv(.naked) void {
    asm volatile (
    // x0 = handler address, [sp] = {saved_x0, saved_x30}
    // Move handler address to x30 (we'll restore the real x30 later).
        \\mov x30, x0

        // Restore original x0 from the vector stub's push.
        // The vector stub did: stp x0, x30, [sp, #-16]!
        // So [sp, #0] = original x0, [sp, #8] = original x30.
        \\ldr x0, [sp, #0]

        // Allocate full ArchCpuContext frame (272 bytes) below the 16-byte
        // save area. We adjust sp down by 272 and will store registers there.
        // After this: sp points to ArchCpuContext base.
        // The 16-byte save area is at sp + 272.
        \\sub sp, sp, #272

        // Save x0-x29 via stp pairs into the ArchCpuContext.
        \\stp x0, x1, [sp, #0]
        \\stp x2, x3, [sp, #16]
        \\stp x4, x5, [sp, #32]
        \\stp x6, x7, [sp, #48]
        \\stp x8, x9, [sp, #64]
        \\stp x10, x11, [sp, #80]
        \\stp x12, x13, [sp, #96]
        \\stp x14, x15, [sp, #112]
        \\stp x16, x17, [sp, #128]
        \\stp x18, x19, [sp, #144]
        \\stp x20, x21, [sp, #160]
        \\stp x22, x23, [sp, #176]
        \\stp x24, x25, [sp, #192]
        \\stp x26, x27, [sp, #208]
        \\stp x28, x29, [sp, #224]

        // Restore original x30 from the vector stub's save area (now at sp + 272 + 8).
        \\ldr x10, [sp, #280]
        \\str x10, [sp, #240]

        // Save SP_EL0 at offset 248 (ARM ARM D1.10).
        \\mrs x10, sp_el0
        \\str x10, [sp, #248]

        // Save ELR_EL1 at offset 256, SPSR_EL1 at offset 264.
        // ARM ARM D13.2.36 (ELR_EL1), D13.2.127 (SPSR_EL1).
        \\mrs x10, elr_el1
        \\mrs x11, spsr_el1
        \\stp x10, x11, [sp, #256]

        // Call the handler: x0 = pointer to ArchCpuContext, x30 = handler address.
        \\mov x0, sp
        \\blr x30

        // Restore ELR_EL1 and SPSR_EL1 from the context.
        \\ldp x10, x11, [sp, #256]
        \\msr elr_el1, x10
        \\msr spsr_el1, x11

        // Restore SP_EL0.
        \\ldr x10, [sp, #248]
        \\msr sp_el0, x10

        // Restore x30 from offset 240.
        \\ldr x30, [sp, #240]

        // Restore x0-x29.
        \\ldp x28, x29, [sp, #224]
        \\ldp x26, x27, [sp, #208]
        \\ldp x24, x25, [sp, #192]
        \\ldp x22, x23, [sp, #176]
        \\ldp x20, x21, [sp, #160]
        \\ldp x18, x19, [sp, #144]
        \\ldp x16, x17, [sp, #128]
        \\ldp x14, x15, [sp, #112]
        \\ldp x12, x13, [sp, #96]
        \\ldp x10, x11, [sp, #80]
        \\ldp x8, x9, [sp, #64]
        \\ldp x6, x7, [sp, #48]
        \\ldp x4, x5, [sp, #32]
        \\ldp x2, x3, [sp, #16]
        \\ldp x0, x1, [sp, #0]

        // Deallocate ArchCpuContext frame (272) + vector stub save area (16).
        // ARM ARM D1.10.1: ERET restores PC from ELR_EL1, PSTATE from SPSR_EL1.
        \\add sp, sp, #288
        \\eret
    );
}

/// Write VBAR_EL1 to install the exception vector table.
/// ARM ARM D13.2.143: VBAR_EL1 holds the base address of the EL1
/// exception vector table. The address must be 2048-byte aligned
/// (bits [10:0] are RES0).
pub fn install() void {
    const table_addr = @intFromPtr(&exceptionVectorTable);
    asm volatile ("msr vbar_el1, %[addr]"
        :
        : [addr] "r" (table_addr),
    );
    // ISB ensures the new VBAR_EL1 is visible before the next exception.
    asm volatile ("isb");
}

// ── Exception Handlers ──────────────────────────────────────────────────

/// Read ESR_EL1 -- Exception Syndrome Register.
/// ARM ARM D13.2.37.
fn readEsrEl1() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], esr_el1"
        : [val] "=r" (val),
    );
    return val;
}

/// Read FAR_EL1 -- Fault Address Register.
/// ARM ARM D13.2.40: holds the faulting virtual address for Data Aborts,
/// Instruction Aborts, PC alignment faults, and watchpoint exceptions.
fn readFarEl1() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], far_el1"
        : [val] "=r" (val),
    );
    return val;
}

/// Handler for synchronous exceptions from Lower EL (EL0 userspace).
/// ARM ARM D1.10.2, offset 0x400.
///
/// Dispatches based on ESR_EL1 Exception Class:
///   EC=0x15 (SVC64): syscall -- dispatch to syscall handler.
///   EC=0x24 (Data Abort from lower EL): page fault -- dispatch to fault handler.
///   EC=0x20 (Instruction Abort from lower EL): page fault -- dispatch to fault handler.
///   Others: kill the faulting process with an appropriate FaultReason.
fn handleSyncLowerEl(ctx: *ArchCpuContext) callconv(.c) void {
    const esr = readEsrEl1();
    const ec = extractEc(esr);

    switch (ec) {
        .svc_aarch64 => {
            const result = syscall_dispatch.dispatch(ctx);
            ctx.regs.x0 = @bitCast(result.ret);
            ctx.regs.x1 = result.ret2;
        },

        .data_abort_lower_el => {
            const is_write = isWriteFault(esr);
            const pf_ctx = PageFaultContext{
                .faulting_address = readFarEl1(),
                .is_kernel_privilege = false,
                .is_write = is_write,
                .is_exec = false,
                .rip = ctx.elr_el1,
                .user_ctx = ctx,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        .instruction_abort_lower_el => {
            const pf_ctx = PageFaultContext{
                .faulting_address = readFarEl1(),
                .is_kernel_privilege = false,
                .is_write = false,
                .is_exec = true,
                .rip = ctx.elr_el1,
                .user_ctx = ctx,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        .pc_alignment => {
            faultOrKillUser(ctx, .alignment_fault, readFarEl1());
        },

        .sp_alignment => {
            faultOrKillUser(ctx, .alignment_fault, ctx.sp_el0);
        },

        .breakpoint_lower_el, .brk_instruction => {
            faultOrKillUser(ctx, .breakpoint, ctx.elr_el1);
        },

        .software_step_lower_el, .watchpoint_lower_el => {
            // Single-step / watchpoint from userspace: resume silently.
            return;
        },

        else => {
            faultOrKillUser(ctx, .protection_fault, ctx.elr_el1);
        },
    }
}

/// Handler for IRQ from Lower EL (EL0 userspace).
/// ARM ARM D1.10.2, offset 0x480.
///
/// Acknowledges the interrupt via GIC (IHI 0069H, Section 12.11.1:
/// ICC_IAR1_EL1), dispatches to the registered device handler, and
/// signals end-of-interrupt (ICC_EOIR1_EL1).
fn handleIrqLowerEl(ctx: *ArchCpuContext) callconv(.c) void {
    const intid = gic.acknowledgeInterrupt();

    // INTID 1023 = spurious interrupt (IHI 0069H, Section 12.11.1).
    // No EOI needed for spurious interrupts.
    if (intid == 1023) return;

    // EOI must be issued BEFORE dispatchIrq because the timer / scheduler
    // IPI paths can call `scheduler.switchTo`, which is `noreturn` and
    // ERETs to a different thread. Anything queued after dispatchIrq is
    // unreachable on a context switch, leaving the interrupt permanently
    // in the active state and masking every subsequent delivery of that
    // same priority (IHI 0069H §4.6: an active interrupt blocks pending).
    gic.endOfInterrupt(intid);
    dispatchIrq(intid, ctx, .user);
}

/// Handler for synchronous exceptions from Current EL (kernel-mode).
/// ARM ARM D1.10.2, offset 0x200.
///
/// Only Data Aborts (demand paging) are expected in kernel mode.
/// All other exceptions are fatal.
fn handleSyncCurrentEl(ctx: *ArchCpuContext) callconv(.c) void {
    const esr = readEsrEl1();
    const ec = extractEc(esr);

    switch (ec) {
        .data_abort_same_el => {
            const is_write = isWriteFault(esr);
            const pf_ctx = PageFaultContext{
                .faulting_address = readFarEl1(),
                .is_kernel_privilege = true,
                .is_write = is_write,
                .is_exec = false,
                .rip = ctx.elr_el1,
                .user_ctx = null,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        .instruction_abort_same_el => {
            const pf_ctx = PageFaultContext{
                .faulting_address = readFarEl1(),
                .is_kernel_privilege = true,
                .is_write = false,
                .is_exec = true,
                .rip = ctx.elr_el1,
                .user_ctx = null,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        else => {
            arch.print("KERNEL EXCEPTION: EC=0x{x} ESR=0x{x} ELR=0x{x} FAR=0x{x}\n", .{
                @intFromEnum(ec), esr, ctx.elr_el1, readFarEl1(),
            });
            @panic("Unhandled kernel synchronous exception");
        },
    }
}

/// Handler for IRQ from Current EL (kernel-mode).
/// ARM ARM D1.10.2, offset 0x280.
fn handleIrqCurrentEl(ctx: *ArchCpuContext) callconv(.c) void {
    const intid = gic.acknowledgeInterrupt();

    if (intid == 1023) return;

    // EOI before dispatch — see handleIrqLowerEl for rationale.
    gic.endOfInterrupt(intid);
    dispatchIrq(intid, ctx, .kernel);
}

/// Panic handler for unexpected/unimplemented vector entries.
fn handleUnexpected(ctx: *ArchCpuContext) callconv(.c) void {
    const esr = readEsrEl1();
    arch.print("UNEXPECTED EXCEPTION: ESR=0x{x} ELR=0x{x} FAR=0x{x}\n", .{
        esr, ctx.elr_el1, readFarEl1(),
    });
    @panic("Unexpected exception vector taken");
}

/// Dispatch a GIC interrupt to the appropriate handler.
/// The INTID namespace (IHI 0069H, Section 2.2):
///   0-15:    SGI (Software Generated Interrupts / IPIs)
///   16-31:   PPI (Private Peripheral Interrupts, e.g. timer)
///   32-1019: SPI (Shared Peripheral Interrupts, e.g. devices)
///
/// PPI 30 is the non-secure EL1 physical timer interrupt (ARM ARM
/// D11.2.4); this is the scheduler's preemption tick. It is routed
/// directly to `sched.schedTimerHandler`, equivalent of the x64
/// LAPIC-timer IDT vector.
fn dispatchIrq(intid: u32, ctx: *ArchCpuContext, privilege: zag.perms.privilege.PrivilegePerm) void {
    switch (intid) {
        // SGI 0 — scheduler IPI raised by `triggerSchedulerInterrupt` on
        // aarch64 (see `arch/dispatch.zig sched_ipi_vector`). Used by both
        // explicit `thread_yield` syscalls and cross-core wake-ups. Dispatch
        // it through the same path as the timer tick so the scheduler picks
        // a new runnable thread on this core.
        0 => {
            const sched_ctx = scheduler.SchedInterruptContext{
                .privilege = privilege,
                .thread_ctx = ctx,
            };
            scheduler.schedTimerHandler(sched_ctx);
        },
        27 => {
            // Mask the virtual timer while we run the scheduler tick.
            // schedTimerHandler will re-arm via `armInterruptTimer`
            // which writes ENABLE=1, IMASK=0 and thereby unmasks again.
            // Without masking first, ISTATUS stays asserted and the
            // GIC would immediately re-deliver the PPI after EOI.
            // ARM ARM D13.8.20: CNTV_CTL_EL0 IMASK (bit 1).
            asm volatile ("msr cntv_ctl_el0, %[val]"
                :
                : [val] "r" (@as(u64, 0x3)), // ENABLE=1, IMASK=1
            );
            const sched_ctx = scheduler.SchedInterruptContext{
                .privilege = privilege,
                .thread_ctx = ctx,
            };
            scheduler.schedTimerHandler(sched_ctx);
        },
        else => {
            arch.print("K: IRQ intid={d} (unhandled)\n", .{intid});
        },
    }
}

/// Attempt to notify the process's fault handler; if none is registered,
/// kill the process. Used for userspace synchronous exceptions that are
/// not syscalls or page faults (e.g. alignment, illegal instruction).
fn faultOrKillUser(ctx: *ArchCpuContext, reason: FaultReason, fault_addr: u64) void {
    const thread = scheduler.currentThread() orelse
        @panic("user exception with no current thread");
    arch.print("K: EXCEPTION pid={d} EC reason={d} addr=0x{x}\n", .{
        thread.process.pid, @intFromEnum(reason), fault_addr,
    });
    if (thread.process.faultBlock(thread, reason, fault_addr, ctx.elr_el1, ctx)) {
        arch.enableInterrupts();
        scheduler.yield();
        return;
    }
    thread.process.kill(reason);
    arch.enableInterrupts();
    while (true) arch.halt();
}
