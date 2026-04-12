const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;

const InterruptHandler = idt.interruptHandler;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

pub const ArchCpuContext = cpu.Context;

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
    tlb_shootdown = 0xFD,
    sched = 0xFE,
    spurious = 0xFF,
};

pub const VectorKind = enum {
    exception,
    external,
    software,
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
    ctx.regs.rax = @bitCast(result.rax);
    ctx.regs.rdx = result.rdx;
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

        // ── FXSAVE (Intel SDM Vol 1 §10.5) ──────────────────────────
        \\subq $512, %%rsp
        \\fxsave (%%rsp)

        // ── Dispatch ─────────────────────────────────────────────────
        \\lea 512(%%rsp), %%rdi       // RDI = &Context
        \\call syscallDispatch

        // ── Restore FPU + GPRs ───────────────────────────────────────
        \\fxrstor (%%rsp)
        \\addq $512, %%rsp
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
    // Match the real interrupt entry layout. TSS.RSP0 = kernel_stack.top (page-aligned).
    // CPU pushes 5 words (40 bytes), stub pushes 2 words (16 bytes),
    // prologue pushes 15 GP regs (120 bytes) = 176 total. Then FXSAVE area below.
    // kstack_top from caller is alignStack(top) = top-8, but we need the raw top
    // (same as TSS.RSP0) so FXSAVE lands at a 16-byte aligned address.
    // Undo the -8 from alignStack:
    const raw_top: u64 = (kstack_top.addr + 8 + 15) & ~@as(u64, 15);
    const ctx_addr: u64 = raw_top - @sizeOf(cpu.Context);
    const fxsave_addr: u64 = ctx_addr - cpu.fxsave_size;
    var ctx: *cpu.Context = @ptrFromInt(ctx_addr);

    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);

    // Zero the entire region (FXSAVE area + Context) to avoid movaps
    // alignment issues and to give a clean initial SSE state.
    const full_bytes: [*]u8 = @ptrFromInt(fxsave_addr);
    @memset(full_bytes[0 .. cpu.fxsave_size + @sizeOf(cpu.Context)], 0);

    // Set FXSAVE defaults: FCW=0x037F (mask all FPU exceptions),
    // MXCSR=0x1F80 (mask all SSE exceptions, round-to-nearest)
    const fxsave: [*]u8 = @ptrFromInt(fxsave_addr);
    @as(*align(1) u16, @ptrCast(fxsave[0..2])).* = 0x037F; // FCW
    @as(*align(1) u32, @ptrCast(fxsave[24..28])).* = 0x1F80; // MXCSR
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
        // Subtract 8 to simulate a CALL instruction's return-address push,
        // so the entry function sees RSP ≡ 8 (mod 16) per the SysV ABI.
        // The slot at ctx_addr-8 falls in the (already-restored) FXSAVE area
        // and is zero, which is fine — kernel entry points never return.
        ctx.rsp = ctx_addr - 8;
    }

    return @ptrCast(ctx);
}

pub fn switchTo(thread: *Thread) void {
    const core_id = apic.coreID();
    const kstack = thread.kernel_stack.top.addr;
    gdt.coreTss(core_id).rsp0 = kstack;
    updateScratchKernelRsp(core_id, kstack);

    const new_root = thread.process.addr_space_root;
    if (new_root.addr != arch.getAddrSpaceRoot().addr) {
        arch.swapAddrSpace(new_root);
        std.debug.assert(arch.getAddrSpaceRoot().addr == new_root.addr);
    }

    apic.endOfInterrupt();
    // ctx points to Context (GP regs). FXSAVE area is 512 bytes below.
    // Epilogue expects RSP at FXSAVE area.
    asm volatile (
        \\movq %[new_stack], %%rsp
        \\subq $512, %%rsp
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
        // Save SSE/x87 state (512 bytes below GP regs)
        \\subq $512, %rsp
        \\fxsave (%rsp)
        \\
        // Pass Context address (GP regs, 512 bytes above FXSAVE) to handler
        \\lea 512(%rsp), %rdi
        \\call dispatchInterrupt
        \\
        \\jmp interruptStubEpilogue
    );
}

export fn interruptStubEpilogue() callconv(.naked) void {
    asm volatile (
        // Restore SSE/x87 state
        \\fxrstor (%rsp)
        \\addq $512, %rsp
        \\
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
