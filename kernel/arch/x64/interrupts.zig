const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const fpu = zag.sched.fpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const paging = zag.arch.x64.paging;
const scheduler = zag.sched.scheduler;

const InterruptHandler = idt.interruptHandler;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const ArchCpuContext = cpu.Context;

/// Number of general-purpose registers saved in a fault snapshot.
/// x86-64: 15 (rax-r15 minus rsp).
pub const fault_gpr_count: usize = 15;

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

pub const PageFaultContext = struct {
    faulting_address: u64,
    is_kernel_privilege: bool,
    is_write: bool,
    is_exec: bool,
    rip: u64 = 0,
    /// Pointer to the user iret `cpu.Context` captured by the stub, i.e.
    /// the actual register frame that will be restored by the stub epilogue
    /// iret. Used so `fault_reply(FAULT_RESUME_MODIFIED)` can patch the
    /// real user frame instead of `thread.ctx` (which after yield points at
    /// a kernel-mode context). Null for kernel-mode faults.
    user_ctx: ?*ArchCpuContext = null,
};

pub const IntVecs = enum(u8) {
    pmu = 0xFB,
    kprof_dump = 0xFC,
    tlb_shootdown = 0xFD,
    sched = 0xFE,
    spurious = 0xFF,
    fpu_flush = 0xFA,
};

pub const VectorKind = enum {
    exception,
    external,
};

const VectorEntry = struct {
    handler: ?Handler = null,
    kind: VectorKind = .external,
};

const Handler = *const fn (*cpu.Context) void;

pub const stubs: [256]InterruptHandler = blk: {
    var arr: [256]InterruptHandler = undefined;
    for (0..256) |i| {
        arr[i] = getInterruptStub(i, pushes_err[i]);
    }
    break :blk arr;
};

const pushes_err = blk: {
    var a: [256]bool = .{false} ** 256;
    a[8] = true;
    a[10] = true;
    a[11] = true;
    a[12] = true;
    a[13] = true;
    a[14] = true;
    a[17] = true;
    a[20] = true;
    a[30] = true;
    break :blk a;
};

var vector_table: [256]VectorEntry = .{VectorEntry{}} ** 256;

/// Per-CPU scratch space for SYSCALL entry. SWAPGS gives us access to
/// this via the GS segment base. Layout: [0]=kernel_rsp, [8]=user_rsp.
pub const SyscallScratch = extern struct {
    kernel_rsp: u64,
    user_rsp: u64,
};

pub var per_cpu_scratch: [64]SyscallScratch = [_]SyscallScratch{.{ .kernel_rsp = 0, .user_rsp = 0 }} ** 64;

/// Set KernelGsBase MSR for this core so SWAPGS can access per-CPU scratch.
/// Must be called on each core during init, after APIC is available.
pub fn initSyscallScratch(core_id: u64) void {
    const ia32_kernel_gs_base: u32 = 0xC0000102;
    cpu.wrmsr(ia32_kernel_gs_base, @intFromPtr(&per_cpu_scratch[core_id]));
}

/// Update per-CPU scratch kernel_rsp. Called from switchTo on every
/// context switch, mirroring the TSS.RSP0 update.
pub fn updateScratchKernelRsp(core_id: u64, kernel_rsp: u64) void {
    per_cpu_scratch[core_id].kernel_rsp = kernel_rsp;
}

/// Syscall dispatch — exported so the SYSCALL asm entry can call it.
/// Wraps the generic syscall.dispatch and writes results back to ctx.
export fn syscallDispatch(ctx: *cpu.Context) void {
    const result = zag.syscall.dispatch.dispatch(ctx);
    ctx.regs.rax = @bitCast(result.ret);
    ctx.regs.rdx = result.ret2;
}

/// SYSCALL entry point. Builds an iret-compatible cpu.Context frame so
/// the existing dispatch and context-switch paths work unchanged.
///
/// On entry (Intel SDM Vol 2B, "SYSCALL—Fast System Call"):
///   RCX = user RIP, R11 = user RFLAGS, RSP = user stack (unchanged).
///   CS/SS loaded from IA32_STAR[47:32]. RFLAGS masked by IA32_FMASK.
///
/// SWAPGS (Intel SDM Vol 3A §5.8.8) swaps GS.base ↔ IA32_KERNEL_GS_BASE.
/// KernelGsBase points to per-CPU SyscallScratch: [0]=kernel_rsp, [8]=scratch.
///
/// On exit (Intel SDM Vol 2B, "SYSRET—Return From Fast System Call"):
///   RIP=RCX, RFLAGS=R11&3C7FD7H|2, CS=STAR[63:48]+16|3, SS=STAR[63:48]+8|3.
///   Non-canonical RCX → #GP at CPL3 on kernel stack; checked before SYSRET.
pub export fn syscallEntry() callconv(.naked) void {
    // cpu.Context layout (low addr → high addr, each field 8 bytes):
    //   [RSP+0]   r15          ─┐
    //   [RSP+8]   r14           │
    //   [RSP+16]  r13           │
    //   [RSP+24]  r12           │
    //   [RSP+32]  r11           │ Registers (15 GPRs = 120 bytes)
    //   [RSP+40]  r10           │
    //   [RSP+48]  r9            │
    //   [RSP+56]  r8            │
    //   [RSP+64]  rdi           │
    //   [RSP+72]  rsi           │
    //   [RSP+80]  rbp           │
    //   [RSP+88]  rbx           │
    //   [RSP+96]  rdx           │
    //   [RSP+104] rcx           │
    //   [RSP+112] rax          ─┘
    //   [RSP+120] int_num       ─┐ stub fields (16 bytes)
    //   [RSP+128] err_code      ─┘
    //   [RSP+136] rip           ─┐
    //   [RSP+144] cs             │ iret frame (40 bytes)
    //   [RSP+152] rflags         │
    //   [RSP+160] rsp            │
    //   [RSP+168] ss            ─┘
    asm volatile (
    // ── Stack switch via SWAPGS (Intel SDM Vol 3A §5.8.8) ────────
        \\swapgs                       // GS.base → per-CPU SyscallScratch
        \\movq %%rsp, %%gs:8          // scratch.user_rsp = user RSP
        \\movq %%gs:0, %%rsp          // RSP = kernel stack top

        // Allocate the full Context frame (176 bytes).
        \\subq $176, %%rsp

        // Save user RBP to its slot FIRST, so we can use RBP as scratch.
        \\movq %%rbp, 80(%%rsp)       // ctx.regs.rbp = user RBP

        // Ferry user RSP from gs:scratch into the frame via RBP.
        \\movq %%gs:8, %%rbp          // RBP = user RSP (from scratch)
        \\movq %%rbp, 160(%%rsp)      // ctx.rsp = user RSP

        // Done with per-CPU data. Restore user GS base so kernel code
        // that context-switches (IRETQ path) leaves GS in the right state.
        \\swapgs                       // GS.base restored to user value

        // ── Write iret frame + stub fields ───────────────────────────
        \\movq $0x1b, 168(%%rsp)      // ctx.ss  = USER_DATA(0x18) | RPL3
        \\movq %%r11, 152(%%rsp)      // ctx.rflags = R11 (SYSCALL saved)
        \\movq $0x23, 144(%%rsp)      // ctx.cs  = USER_CODE(0x20) | RPL3
        \\movq %%rcx, 136(%%rsp)      // ctx.rip = RCX (SYSCALL saved)
        \\movq $0, 128(%%rsp)         // ctx.err_code = 0
        \\movq $0x80, 120(%%rsp)      // ctx.int_num  = 0x80

        // ── Write remaining 14 GPRs (RBP already saved above) ───────
        \\movq %%rax, 112(%%rsp)      // ctx.regs.rax
        \\movq %%rcx, 104(%%rsp)      // ctx.regs.rcx
        \\movq %%rdx, 96(%%rsp)       // ctx.regs.rdx
        \\movq %%rbx, 88(%%rsp)       // ctx.regs.rbx
        // rbp already at 80(%%rsp)
        \\movq %%rsi, 72(%%rsp)       // ctx.regs.rsi
        \\movq %%rdi, 64(%%rsp)       // ctx.regs.rdi
        \\movq %%r8,  56(%%rsp)       // ctx.regs.r8
        \\movq %%r9,  48(%%rsp)       // ctx.regs.r9
        \\movq %%r10, 40(%%rsp)       // ctx.regs.r10
        \\movq %%r11, 32(%%rsp)       // ctx.regs.r11
        \\movq %%r12, 24(%%rsp)       // ctx.regs.r12
        \\movq %%r13, 16(%%rsp)       // ctx.regs.r13
        \\movq %%r14, 8(%%rsp)        // ctx.regs.r14
        \\movq %%r15, 0(%%rsp)        // ctx.regs.r15

        // ── Dispatch ─────────────────────────────────────────────────
        // Lazy FPU: no FXSAVE here. The user's FP/SIMD register file is
        // left in place across the syscall. The kernel is built without
        // SSE (see -mno-sse2/-mno-avx in build.zig), so it cannot
        // clobber XMM/YMM state. The thread is still the FPU owner on
        // this core (last_fpu_owner[core] == thread), so on iretq the
        // user can keep using FP without any trap.
        \\movq %%rsp, %%rdi            // RDI = &Context
        \\call syscallDispatch

        // ── Restore GPRs ─────────────────────────────────────────────
        \\movq 0(%%rsp), %%r15
        \\movq 8(%%rsp), %%r14
        \\movq 16(%%rsp), %%r13
        \\movq 24(%%rsp), %%r12
        \\movq 32(%%rsp), %%r11
        \\movq 40(%%rsp), %%r10
        \\movq 48(%%rsp), %%r9
        \\movq 56(%%rsp), %%r8
        \\movq 64(%%rsp), %%rdi
        \\movq 72(%%rsp), %%rsi
        \\movq 80(%%rsp), %%rbp
        \\movq 88(%%rsp), %%rbx
        \\movq 96(%%rsp), %%rdx
        \\movq 104(%%rsp), %%rcx
        \\movq 112(%%rsp), %%rax

        // ── Return to userspace via IRETQ ─────────────────────��──────
        // IRETQ properly loads CS/SS from the stack frame, avoiding
        // SYSRET's reliance on the hidden descriptor cache which is
        // unreliable under KVM. SYSCALL entry is still used for the
        // fast entry path; only the return uses IRETQ.
        \\addq $120, %%rsp             // skip GPRs (RSP now at int_num)
        \\addq $16, %%rsp              // skip int_num + err_code → iret frame
        \\iretq
    );
}

pub fn prepareThreadContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
    arg: u64,
) *ArchCpuContext {
    @setRuntimeSafety(false);
    // Match the real interrupt entry layout. TSS.RSP0 = kernel_stack.top
    // (page-aligned). CPU pushes 5 words (40 bytes), stub pushes 2 words
    // (16 bytes), prologue pushes 15 GP regs (120 bytes) = 176 total.
    // Under lazy FPU there is no FXSAVE area below Context — the per-
    // thread `fpu_state` buffer lives in the Thread struct, not on the
    // kernel stack.
    // kstack_top from caller is alignStack(top) = top-8, undo the -8:
    const raw_top: u64 = (kstack_top.addr + 8 + 15) & ~@as(u64, 15);
    const ctx_addr: u64 = raw_top - @sizeOf(cpu.Context);
    var ctx: *cpu.Context = @ptrFromInt(ctx_addr);

    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);

    @memset(std.mem.asBytes(ctx), 0);

    ctx.regs.rdi = arg;
    ctx.rip = @intFromPtr(entry);
    ctx.rflags = 0x202;

    if (ustack_top != null) {
        ctx.cs = gdt.USER_CODE_OFFSET | ring_3;
        ctx.ss = gdt.USER_DATA_OFFSET | ring_3;
        ctx.rsp = ustack_top.?.addr;
    } else {
        ctx.cs = gdt.KERNEL_CODE_OFFSET;
        ctx.ss = gdt.KERNEL_DATA_OFFSET;
        // Subtract 8 to simulate a CALL instruction's return-address
        // push so the entry function sees RSP ≡ 8 (mod 16) per the
        // SysV ABI. Kernel entry points never return.
        ctx.rsp = ctx_addr - 8;
    }

    return @ptrCast(ctx);
}

pub fn switchTo(thread: *Thread) void {
    const core_id = apic.coreID();
    const kstack = thread.kernel_stack.top.addr;
    gdt.coreTss(core_id).rsp0 = kstack;
    updateScratchKernelRsp(core_id, kstack);

    // self-alive: `thread` was selected by the scheduler for this
    // core; its owning Process is kept alive by the thread through
    // the dispatch window, so reading `addr_space_root` / `_id`
    // directly without a lock is sound.
    const proc = thread.process.ptr;
    const new_root = proc.addr_space_root;
    if (new_root.addr != paging.getAddrSpaceRoot().addr) {
        paging.swapAddrSpace(new_root, proc.addr_space_id);
        std.debug.assert(paging.getAddrSpaceRoot().addr == new_root.addr);
    }

    // Lazy FPU: TS should be clear iff `thread` is the current owner
    // on this core, set otherwise. Track the desired state and only
    // touch CR0 when it changes — MOV-to-CR0 vmexits under KVM at
    // ~1k+ cycles per write, so skipping no-op writes is critical.
    //
    // Cross-core migration: if the thread's FP state lives in a
    // different core's regs, flush it out via IPI first so the trap
    // handler restores from the right buffer contents.
    //
    // Skipped under -Dlazy_fpu=false (eager baseline): the FPU regs
    // were already swapped in scheduler.switchToWithPmu and CR0.TS is
    // never armed, so no migration flush is needed either.
    if (comptime fpu.lazy_enabled) {
        fpu.migrateFlush(thread);
        const cid: u8 = @truncate(core_id);
        const desired_armed = (scheduler.last_fpu_owner[cid] != thread);
        if (desired_armed != scheduler.fpu_trap_armed[cid]) {
            if (desired_armed) cpu.fpuArmTrap() else cpu.fpuClearTrap();
            scheduler.fpu_trap_armed[cid] = desired_armed;
        }
    }

    apic.endOfInterrupt();
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp interruptStubEpilogue
        :
        : [new_stack] "r" (@intFromPtr(thread.ctx)),
    );
}

pub fn getInterruptStub(comptime int_num: u8, comptime does_push_err: bool) InterruptHandler {
    return struct {
        fn stub() callconv(.naked) void {
            if (does_push_err) {
                asm volatile (
                    \\pushq %[num]
                    \\jmp interruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            } else {
                asm volatile (
                    \\pushq $0
                    \\pushq %[num]
                    \\jmp interruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            }
        }
    }.stub;
}

pub fn registerVector(
    vector: u8,
    handler: Handler,
    kind: VectorKind,
) void {
    std.debug.assert(vector_table[vector].handler == null);
    vector_table[vector] = .{
        .handler = handler,
        .kind = kind,
    };
}

export fn interruptStubPrologue() callconv(.naked) void {
    // Re-arm SMAP before any kernel work runs. CLAC is a no-op on CPUs
    // that lack SMAP (RFLAGS.AC is already 0 for CPL-0 code that never
    // set it) but critically defends against an adversarial user that
    // sets RFLAGS.AC=1 via POPFQ before issuing a syscall — without this
    // the syscall dispatch would run with AC=1 and bypass SMAP for every
    // raw user pointer access. IRETQ in `interruptStubEpilogue` restores
    // the interrupted context's RFLAGS (including AC) from the iret
    // frame, so kernel code interrupted mid-`userAccessBegin` resumes
    // with AC=1 as expected. Single-byte-equivalent, no register clobber.
    asm volatile (
        \\clac
        \\pushq %rax
        \\pushq %rcx
        \\pushq %rdx
        \\pushq %rbx
        \\pushq %rbp
        \\pushq %rsi
        \\pushq %rdi
        \\pushq %r8
        \\pushq %r9
        \\pushq %r10
        \\pushq %r11
        \\pushq %r12
        \\pushq %r13
        \\pushq %r14
        \\pushq %r15
        \\
        // Lazy FPU: no FXSAVE here. Kernel is built without SSE so it
        // cannot dirty the FP/SIMD register file across the handler.
        // The previous owner of the FPU on this core (which may be the
        // userspace thread we just interrupted, or some other thread
        // whose state has been parked here) keeps its regs in place.
        \\movq %rsp, %rdi
        \\call dispatchInterrupt
        \\
        \\jmp interruptStubEpilogue
    );
}

export fn interruptStubEpilogue() callconv(.naked) void {
    asm volatile (
        \\popq %r15
        \\popq %r14
        \\popq %r13
        \\popq %r12
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rdi
        \\popq %rsi
        \\popq %rbp
        \\popq %rbx
        \\popq %rdx
        \\popq %rcx
        \\popq %rax
        \\
        \\addq $16, %%rsp
        \\iretq
    );
}

pub fn serializeFaultRegs(ctx: *const ArchCpuContext) FaultRegSnapshot {
    const r = &ctx.regs;
    return .{
        .ip = ctx.rip,
        .flags = ctx.rflags,
        .sp = ctx.rsp,
        .gprs = .{
            r.r15, r.r14, r.r13, r.r12, r.r11, r.r10, r.r9,  r.r8,
            r.rdi, r.rsi, r.rbp, r.rbx, r.rdx, r.rcx, r.rax,
        },
    };
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
        .num = ctx.regs.rax,
        .arg0 = ctx.regs.rdi,
        .arg1 = ctx.regs.rsi,
        .arg2 = ctx.regs.rdx,
        .arg3 = ctx.regs.r10,
        .arg4 = ctx.regs.r8,
    };
}

pub fn getSyscallReturn(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.rax;
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rax = value;
}

pub fn getIpcHandle(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.r13;
}

pub fn getIpcMetadata(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.r14;
}

pub fn setIpcMetadata(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.r14 = value;
}

pub fn getIpcPayloadWords(ctx: *const ArchCpuContext) [5]u64 {
    return .{ ctx.regs.rdi, ctx.regs.rsi, ctx.regs.rdx, ctx.regs.r8, ctx.regs.r9 };
}

pub fn copyIpcPayload(dst: *ArchCpuContext, src: *const ArchCpuContext, word_count: u3) void {
    if (word_count >= 1) dst.regs.rdi = src.regs.rdi;
    if (word_count >= 2) dst.regs.rsi = src.regs.rsi;
    if (word_count >= 3) dst.regs.rdx = src.regs.rdx;
    if (word_count >= 4) dst.regs.r8 = src.regs.r8;
    if (word_count >= 5) dst.regs.r9 = src.regs.r9;
}

pub const IpcPayloadSnapshot = struct { words: [5]u64 };

pub fn saveIpcPayload(ctx: *const ArchCpuContext) IpcPayloadSnapshot {
    return .{ .words = getIpcPayloadWords(ctx) };
}

pub fn restoreIpcPayload(ctx: *ArchCpuContext, words: [5]u64) void {
    ctx.regs.rdi = words[0];
    ctx.regs.rsi = words[1];
    ctx.regs.rdx = words[2];
    ctx.regs.r8 = words[3];
    ctx.regs.r9 = words[4];
}

pub fn applyFaultRegs(ctx: *ArchCpuContext, snapshot: FaultRegSnapshot) void {
    ctx.rip = snapshot.ip;
    ctx.rflags = snapshot.flags;
    ctx.rsp = snapshot.sp;
    const r = &ctx.regs;
    inline for (.{
        "r15", "r14", "r13", "r12", "r11", "r10", "r9",  "r8",
        "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax",
    }, 0..) |field, i| {
        @field(r, field) = snapshot.gprs[i];
    }
}

export fn dispatchInterrupt(ctx: *cpu.Context) void {
    if (vector_table[ctx.int_num].handler) |h| {
        h(ctx);
        if (vector_table[@intCast(ctx.int_num)].kind == .external) {
            apic.endOfInterrupt();
        }
        return;
    }

    @panic("Unhandled interrupt!");
}
