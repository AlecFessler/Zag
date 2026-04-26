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

const cpu = zag.arch.aarch64.cpu;
const fpu = zag.sched.fpu;
const gic = zag.arch.aarch64.gic;
const paging = zag.arch.aarch64.paging;
const scheduler = zag.sched.scheduler;
const sync_debug = zag.utils.sync.debug;

const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

/// Number of general-purpose registers saved in a fault snapshot.
/// aarch64: 31 (x0-x30).
pub const fault_gpr_count: usize = 31;

/// Size of the register portion of a FaultMessage: ip + flags + sp + GPRs.
pub const fault_regs_size: usize = (3 + fault_gpr_count) * @sizeOf(u64);

/// Total size of a FaultMessage written to userspace (32-byte header + regs).
pub const fault_msg_size: usize = 32 + fault_regs_size;

/// Architecture-neutral snapshot of a faulted thread's registers.
/// Used by fault delivery to serialize register state without the
/// generic kernel referencing arch-specific register names.
pub const FaultRegSnapshot = struct {
    ip: u64,
    flags: u64,
    sp: u64,
    gprs: [fault_gpr_count]u64,
};

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
    // Match the trampoline's stack frame layout: vector-stub 16-byte push
    // followed by the 272-byte ArchCpuContext save = 288 bytes total. On
    // context restore, switchTo() advances SP_EL1 to (ctx + 288) so the
    // frame is fully popped; by aligning the initial ctx at (top - 288)
    // we match the offset a resumed thread would see. The 16 high bytes
    // of the frame are unused (they would hold the vector stub's saved
    // x0/x30 on a real exception path).
    const ctx_addr: u64 = kstack_top.addr - 288;
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
        // Kernel thread: EL1h (M[3:0] = 0x5), DAIF unmasked.
        //
        // EL1h (ARM ARM C5.2.18, value 0b0101) means "EL1 using SP_EL1
        // as the stack pointer". This is the correct mode for kernel
        // threads because a same-EL IRQ taken while a kernel thread is
        // running does NOT change SP — the trampoline pushes its save
        // frame onto the very same SP the interrupted code was using,
        // naturally below the active call-chain frames. The earlier
        // EL1t choice placed kernel-thread C frames on SP_EL0 while
        // the same-EL IRQ trampoline still ran on SP_EL1; switchTo
        // reseeded SP_EL1 = kstack_top on every entry, so a timer IRQ
        // taken during e.g. `sched.yield()` → GIC SGI send would write
        // the 288-byte save frame at [kstack_top-288, kstack_top) —
        // right on top of the thread's live sendIpiToCore / yield /
        // vcpuEntryPoint frames on SP_EL0, which also started at
        // kstack_top. On resume the corrupted saved-LR slots caused
        // the function-epilogue `ret` chain to jump to garbage
        // addresses (observed: ELR=0x7 PC-alignment fault; ELR deep
        // inside exceptionTrampoline). Switching the kernel thread to
        // EL1h eliminates the dual-stack aliasing — see the analogous
        // x86_64 behavior where interrupted kernel code keeps its RSP
        // and the IRQ handler pushes below it without a TSS.rsp0
        // reload.
        //
        // SP_EL0 is unused by the thread (EL1h never reads it) but we
        // still seed it to kstack_top so that serializeFaultRegs and
        // debug dumps report a sensible value.
        //
        // DAIF is unmasked so the idle core can receive IPIs: WFI
        // stalls until an interrupt is pending *and* deliverable, so a
        // masked DAIF.I causes the core to wake, mask pending, WFI
        // again, and effectively ignore every IPI — breaking pinned-
        // thread migration to a formerly-idle core.
        ctx.spsr_el1 = 0x5;
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
    // self-alive: scheduler dispatched `thread` to this core; its
    // owning Process stays alive through the switch window.
    const proc = thread.process.ptr;
    const new_root = proc.addr_space_root;
    if (new_root.addr != paging.getAddrSpaceRoot().addr) {
        paging.swapAddrSpace(new_root, proc.addr_space_id);
    }

    // lockdep: this asm `eret` abandons the call stack the IRQ-handler
    // entry function (handleIrq*El) was using; its `defer exitIrqContext`
    // never executes. Re-balance the per-core IRQ depth here so the
    // counter doesn't drift upward each time an IRQ-driven preemption
    // produces a context switch. No-op when called from non-IRQ paths
    // (the depth is already zero there).
    sync_debug.resetIrqContextOnSwitch();

    // Lazy FPU: CPACR_EL1.FPEN should trap iff `thread` isn't the
    // current FPU owner on this core. Track the desired state in a
    // shadow var and only touch CPACR when it changes — MSRs to
    // CPACR_EL1 ISB-fence and may trap to EL2 under some hypervisors,
    // so skipping no-op writes matters.
    //
    // Cross-core migration: if the thread's FP regs live on another
    // core, IPI it to flush before we can safely fxrstor here.
    //
    // Skipped under -Dlazy_fpu=false (eager baseline): the FPU regs
    // were already swapped in scheduler.switchToWithPmu and FPEN stays
    // open, so no migration flush is needed either.
    if (comptime fpu.lazy_enabled) {
        fpu.migrateFlush(thread);
        const cid: u8 = @truncate(gic.coreID());
        const desired_armed = (scheduler.last_fpu_owner[cid] != thread);
        if (desired_armed != scheduler.fpu_trap_armed[cid]) {
            if (desired_armed) cpu.fpuArmTrap() else cpu.fpuClearTrap();
            scheduler.fpu_trap_armed[cid] = desired_armed;
        }
    }

    // Restore SP_EL1 so the incoming thread's in-progress kernel frames
    // (if it was preempted inside EL1) are reachable, and fresh threads
    // start with their kernel stack empty. `thread.ctx` always points at
    // the saved ArchCpuContext; adding 288 bytes pops the full trampoline
    // frame (16-byte vector-stub push + 272-byte context). Prior to this
    // fix, SP_EL1 was left pointing at whatever stack switchTo() happened
    // to be running on, which was the *outgoing* thread's kernel stack —
    // subsequent exception entries from EL0 then trampled unrelated
    // frames. (x64 handles the EL0-entry case via TSS.rsp0 and never
    // needs this because interrupted kernel code just continues on its
    // own rsp through the standard epilogue.)
    const new_sp = @intFromPtr(thread.ctx) + 288;

    // ctx points to the saved ArchCpuContext (regs x0-x30, sp_el0, elr_el1, spsr_el1).
    // Register file layout: x0 at offset 0, x1 at offset 8, ..., x30 at offset 240,
    // sp_el0 at offset 248, elr_el1 at offset 256, spsr_el1 at offset 264.
    asm volatile (
    // Swap SP_EL1 up front using the input register. After this point we
    // touch no stack memory until ERET, so the value of the old sp is
    // irrelevant. Doing the swap before touching x0 guarantees the
    // %[new_sp] input register hasn't been clobbered yet.
        \\mov sp, %[new_sp]
        \\
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
          [new_sp] "r" (new_sp),
    );
    unreachable;
}

/// Convert an ArchCpuContext into the arch-neutral FaultRegSnapshot.
/// ARM ARM D13.2.36: ELR_EL1 is the faulting instruction pointer.
/// ARM ARM D13.2.127: SPSR_EL1 is the saved processor state (flags equivalent).
pub fn serializeFaultRegs(ctx: *const ArchCpuContext) FaultRegSnapshot {
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
pub fn applyFaultRegs(ctx: *ArchCpuContext, snapshot: FaultRegSnapshot) void {
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

pub const SyscallArgs = struct {
    num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
};

pub fn getSyscallArgs(ctx: *const ArchCpuContext) SyscallArgs {
    return .{
        .num = ctx.regs.x8,
        .arg0 = ctx.regs.x0,
        .arg1 = ctx.regs.x1,
        .arg2 = ctx.regs.x2,
        .arg3 = ctx.regs.x3,
        .arg4 = ctx.regs.x4,
    };
}

pub fn getSyscallReturn(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.x0;
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x0 = value;
}

/// Spec §[event_state] vreg 2 — x1 on aarch64.
pub fn setEventSubcode(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x1 = value;
}

/// Spec §[event_state] vreg 3 — x2 on aarch64.
pub fn setEventAddr(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x2 = value;
}

pub fn getIpcHandle(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.x5;
}

pub fn getIpcMetadata(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.x6;
}

pub fn setIpcMetadata(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x6 = value;
}

pub fn getIpcPayloadWords(ctx: *const ArchCpuContext) [5]u64 {
    return .{ ctx.regs.x0, ctx.regs.x1, ctx.regs.x2, ctx.regs.x3, ctx.regs.x4 };
}

pub fn copyIpcPayload(dst: *ArchCpuContext, src: *const ArchCpuContext, word_count: u3) void {
    if (word_count >= 1) dst.regs.x0 = src.regs.x0;
    if (word_count >= 2) dst.regs.x1 = src.regs.x1;
    if (word_count >= 3) dst.regs.x2 = src.regs.x2;
    if (word_count >= 4) dst.regs.x3 = src.regs.x3;
    if (word_count >= 5) dst.regs.x4 = src.regs.x4;
}

pub const IpcPayloadSnapshot = struct { words: [5]u64 };

pub fn saveIpcPayload(ctx: *const ArchCpuContext) IpcPayloadSnapshot {
    return .{ .words = getIpcPayloadWords(ctx) };
}

pub fn restoreIpcPayload(ctx: *ArchCpuContext, words: [5]u64) void {
    ctx.regs.x0 = words[0];
    ctx.regs.x1 = words[1];
    ctx.regs.x2 = words[2];
    ctx.regs.x3 = words[3];
    ctx.regs.x4 = words[4];
}
