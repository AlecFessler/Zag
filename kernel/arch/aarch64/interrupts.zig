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

const zag = @import("zag");

const arch = zag.arch.dispatch;

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
    far_el1: u64,
    esr_el1: u64,
};

pub fn prepareThreadContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
    arg: u64,
) *ArchCpuContext {
    _ = kstack_top;
    _ = ustack_top;
    _ = entry;
    _ = arg;
    @panic("aarch64 prepareThreadContext not implemented");
}

pub fn switchTo(thread: *Thread) void {
    _ = thread;
    @panic("aarch64 switchTo not implemented");
}

pub fn serializeFaultRegs(ctx: *const ArchCpuContext) arch.FaultRegSnapshot {
    _ = ctx;
    @panic("aarch64 serializeFaultRegs not implemented");
}

pub fn applyFaultRegs(ctx: *ArchCpuContext, snapshot: arch.FaultRegSnapshot) void {
    _ = ctx;
    _ = snapshot;
    @panic("aarch64 applyFaultRegs not implemented");
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
