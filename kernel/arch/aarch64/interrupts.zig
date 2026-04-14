//! AArch64 CPU context, register save/restore, and context switching.
//!
//! This is the aarch64 equivalent of x64/interrupts.zig. It defines the
//! ArchCpuContext layout, implements syscall/IPC register accessors, and
//! provides the thread context switch mechanism.
//!
//! ArchCpuContext layout — saved on exception entry by the vector stub:
//!   x0-x30:    31 general-purpose registers (248 bytes)
//!   sp_el0:    user stack pointer (8 bytes)
//!   elr_el1:   exception link register — return address (8 bytes)
//!   spsr_el1:  saved processor state (8 bytes)
//!   Total: 272 bytes
//!
//! Register conventions (AAPCS64, ARM IHI 0055):
//!   x0-x7:   arguments / return values
//!   x8:      indirect result / syscall number
//!   x9-x15:  caller-saved temporaries
//!   x16-x17: intra-procedure-call scratch (IP0/IP1)
//!   x18:     platform register (reserved)
//!   x19-x28: callee-saved
//!   x29:     frame pointer (FP)
//!   x30:     link register (LR)
//!
//! Syscall register mapping (matches dispatch.zig getSyscallArgs):
//!   x8  = syscall number
//!   x0  = arg0, x1 = arg1, x2 = arg2, x3 = arg3, x4 = arg4
//!   x5  = IPC handle, x6 = IPC metadata
//!   x0-x4 = IPC payload words
//!
//! Exception entry on ARM (ARM ARM D1.10):
//!   On exception, hardware saves PC → ELR_EL1, PSTATE → SPSR_EL1,
//!   sets PSTATE.{DAIF} to mask interrupts, jumps to VBAR_EL1 + offset.
//!   Software must save x0-x30 and SP_EL0 manually in the vector stub.
//!
//! Context switch:
//!   switchTo() restores the target thread's ArchCpuContext and executes ERET.
//!   ARM ARM D1.10.1: ERET restores PC from ELR_EL1, PSTATE from SPSR_EL1.
//!
//! Key functions to implement:
//!   prepareThreadContext()   — allocate ArchCpuContext on kernel stack
//!   switchTo()               — save current context, restore target, ERET
//!   serializeFaultRegs()     — ArchCpuContext → FaultRegSnapshot
//!   applyFaultRegs()         — FaultRegSnapshot → ArchCpuContext
//!   copyIpcPayload()         — copy x0-x4 between contexts
//!   restoreIpcPayload()      — restore x0-x4 from snapshot
//!   setSyscallReturn()       — write x0 in saved context
//!
//! References:
//! - ARM ARM D1.10: Exception entry/return
//! - ARM ARM D13.2.36: ELR_EL1
//! - ARM ARM D13.2.127: SPSR_EL1
//! - ARM IHI 0055: AAPCS64 (calling convention)

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const gic = zag.arch.aarch64.gic;
const paging = zag.arch.aarch64.paging;

const PAddr = zag.memory.address.PAddr;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const Registers = extern struct {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64,
    x30: u64,
};

pub const ArchCpuContext = extern struct {
    regs: Registers,
    sp_el0: u64,
    elr_el1: u64,
    spsr_el1: u64,
};

pub const PageFaultContext = struct {
    faulting_address: u64,
    is_kernel_privilege: bool,
    is_write: bool,
    is_exec: bool,
    rip: u64 = 0,
    user_ctx: ?*ArchCpuContext = null,
};

/// Allocate and initialize an ArchCpuContext at the top of a kernel stack.
///
/// The context is placed at (kstack_top - sizeof(ArchCpuContext)), matching
/// the layout the exception vector stub expects when it saves registers.
///
/// SPSR_EL1 encoding (ARM ARM D13.2.127):
///   M[3:0] = 0b0000 (EL0t) for user threads
///   M[3:0] = 0b0100 (EL1h) for kernel threads
///   DAIF[9:6] = 0b1111 masks all interrupts (set for kernel threads)
///
/// ELR_EL1 (ARM ARM D13.2.36): holds the return address for ERET.
pub fn prepareThreadContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
    arg: u64,
) *ArchCpuContext {
    @setRuntimeSafety(false);
    const ctx_addr: u64 = kstack_top.addr - @sizeOf(ArchCpuContext);
    const ctx: *ArchCpuContext = @ptrFromInt(ctx_addr);

    // Zero the entire context for a clean initial state.
    const bytes: [*]u8 = @ptrFromInt(ctx_addr);
    @memset(bytes[0..@sizeOf(ArchCpuContext)], 0);

    // First argument to entry function (AAPCS64: x0).
    ctx.regs.x0 = arg;

    // Exception return address (ARM ARM D13.2.36).
    ctx.elr_el1 = @intFromPtr(entry);

    if (ustack_top) |ustack| {
        // User thread: EL0t (M[3:0] = 0x0), interrupts unmasked.
        ctx.spsr_el1 = 0x0;
        ctx.sp_el0 = ustack.addr;
    } else {
        // Kernel thread: EL1t (M[3:0] = 0x4), DAIF masked (bits [9:6]).
        //
        // EL1t means "EL1 using SP_EL0 as the stack pointer" (ARM ARM
        // C5.2.18). Unlike EL1h (which uses SP_EL1 and would require
        // mid-switch SP_EL1 clobbering), EL1t lets the existing context
        // restore path use the same SP_EL0 slot for both user and
        // kernel threads. The kernel's own exception handlers still run
        // on SP_EL1 via the SPSel=1 in exception entry, so the kernel
        // thread's stack is separate from the exception-handler stack.
        //
        // Must use kstack_top as SP_EL0 for kernel threads — leaving it
        // zero produces a guaranteed SP-near-zero fault on the very
        // first stack-touching instruction.
        ctx.spsr_el1 = 0x3C4;
        ctx.sp_el0 = kstack_top.addr;
    }

    return ctx;
}

/// Switch to the given thread by restoring its saved ArchCpuContext and
/// executing ERET to return to the thread's execution context.
///
/// Before restoring registers, this function:
///   1. Swaps address space if the target process differs (TTBR0_EL1).
///
/// ARM ARM D1.10.1: ERET restores PC from ELR_EL1, PSTATE from SPSR_EL1.
///
/// The assembly loads the context base into x0, restores SP_EL0, ELR_EL1,
/// and SPSR_EL1 from their slots past the 31 GPRs, then restores x1-x30
/// from the context, and finally restores x0 last (since it held the base
/// pointer), then executes ERET.
pub fn switchTo(thread: *Thread) noreturn {
    const new_root = thread.process.addr_space_root;
    if (new_root.addr != arch.getAddrSpaceRoot().addr) {
        arch.swapAddrSpace(new_root);
    }

    // ctx points to the saved ArchCpuContext (regs x0-x30, sp_el0, elr_el1, spsr_el1).
    // Register file layout: x0 at offset 0, x1 at offset 8, ..., x30 at offset 240,
    // sp_el0 at offset 248, elr_el1 at offset 256, spsr_el1 at offset 264.
    asm volatile (
    // Load context base address into x0.
        \\mov x0, %[ctx]
        \\
        // Restore SP_EL0 (offset 248 = 31*8).
        \\ldr x1, [x0, #248]
        \\msr sp_el0, x1
        \\
        // Restore ELR_EL1 (offset 256 = 32*8).
        \\ldr x1, [x0, #256]
        \\msr elr_el1, x1
        \\
        // Restore SPSR_EL1 (offset 264 = 33*8).
        \\ldr x1, [x0, #264]
        \\msr spsr_el1, x1
        \\
        // Restore x2-x30 from context. x0 and x1 restored last.
        \\ldp x2, x3, [x0, #16]
        \\ldp x4, x5, [x0, #32]
        \\ldp x6, x7, [x0, #48]
        \\ldp x8, x9, [x0, #64]
        \\ldp x10, x11, [x0, #80]
        \\ldp x12, x13, [x0, #96]
        \\ldp x14, x15, [x0, #112]
        \\ldp x16, x17, [x0, #128]
        \\ldp x18, x19, [x0, #144]
        \\ldp x20, x21, [x0, #160]
        \\ldp x22, x23, [x0, #176]
        \\ldp x24, x25, [x0, #192]
        \\ldp x26, x27, [x0, #208]
        \\ldp x28, x29, [x0, #224]
        \\ldr x30, [x0, #240]
        \\
        // Restore x1, then x0 (x0 was the base pointer).
        \\ldr x1, [x0, #8]
        \\ldr x0, [x0, #0]
        \\
        // Return to the thread (ARM ARM D1.10.1).
        \\eret
        :
        : [ctx] "r" (@intFromPtr(thread.ctx)),
    );
    unreachable;
}

/// Convert an ArchCpuContext into the arch-neutral FaultRegSnapshot.
/// ARM ARM D13.2.36: ELR_EL1 is the faulting instruction pointer.
/// ARM ARM D13.2.127: SPSR_EL1 is the saved processor state (flags equivalent).
pub fn serializeFaultRegs(ctx: *const ArchCpuContext) arch.FaultRegSnapshot {
    const r = &ctx.regs;
    return .{
        .ip = ctx.elr_el1,
        .flags = ctx.spsr_el1,
        .sp = ctx.sp_el0,
        .gprs = .{
            r.x0,  r.x1,  r.x2,  r.x3,  r.x4,  r.x5,  r.x6,  r.x7,
            r.x8,  r.x9,  r.x10, r.x11, r.x12, r.x13, r.x14, r.x15,
            r.x16, r.x17, r.x18, r.x19, r.x20, r.x21, r.x22, r.x23,
            r.x24, r.x25, r.x26, r.x27, r.x28, r.x29, r.x30,
        },
    };
}

/// Apply a modified register snapshot back to a faulted thread's context.
/// Reverse of serializeFaultRegs.
pub fn applyFaultRegs(ctx: *ArchCpuContext, snapshot: arch.FaultRegSnapshot) void {
    ctx.elr_el1 = snapshot.ip;
    ctx.spsr_el1 = snapshot.flags;
    ctx.sp_el0 = snapshot.sp;
    const r = &ctx.regs;
    inline for (.{
        "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
        "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    }, 0..) |field, i| {
        @field(r, field) = snapshot.gprs[i];
    }
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x0 = value;
}

pub fn copyIpcPayload(dst: *ArchCpuContext, src: *const ArchCpuContext, word_count: u3) void {
    if (word_count >= 1) dst.regs.x0 = src.regs.x0;
    if (word_count >= 2) dst.regs.x1 = src.regs.x1;
    if (word_count >= 3) dst.regs.x2 = src.regs.x2;
    if (word_count >= 4) dst.regs.x3 = src.regs.x3;
    if (word_count >= 5) dst.regs.x4 = src.regs.x4;
}

pub fn restoreIpcPayload(ctx: *ArchCpuContext, words: [5]u64) void {
    ctx.regs.x0 = words[0];
    ctx.regs.x1 = words[1];
    ctx.regs.x2 = words[2];
    ctx.regs.x3 = words[3];
    ctx.regs.x4 = words[4];
}
