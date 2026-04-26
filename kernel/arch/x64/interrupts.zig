const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const fpu = zag.sched.fpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const paging = zag.arch.x64.paging;
const scheduler = zag.sched.scheduler;
const sync_debug = zag.utils.sync.debug;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const InterruptHandler = idt.interruptHandler;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
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

/// Per-core scratch zone for SYSCALL entry, accessed via `gs:` after
/// `swapgs`. Sized to a full 4 KiB page so other arch fast paths
/// (fault delivery, vm-exit) can grow into the same scratch without
/// changing offsets. Statically allocated in BSS — kernel-mapped at
/// boot, no per-cpu page allocation needed at runtime.
///
/// Offsets are load-bearing — the L4 IPC fast-path asm in
/// `syscallEntry` references them as immediate displacements, not
/// through `@offsetOf`. Reordering fields requires updating that asm.
pub const SyscallScratch = extern struct {
    /// Top of the current EC's kernel stack. Updated by `switchTo`
    /// alongside TSS.RSP0. Read first by entry stub to switch RSP.
    kernel_rsp: u64,
    /// Caller's user RSP at SYSCALL trap. Stashed by entry stub.
    user_rsp: u64,
    /// Caller's user RIP (from RCX, which SYSCALL clobbers). Stashed
    /// so RCX can be reused as scratch.
    user_rip: u64,
    /// Caller's user RFLAGS (from R11, ditto).
    user_rflags: u64,
    /// Pointer to the EC currently dispatched on this core. Updated
    /// by `switchTo`. Read in fast-path entry without further lookup.
    current_ec: u64,
    /// Pointer to that EC's bound CapabilityDomain. Updated alongside
    /// `current_ec` so handle-table walks skip a dereference.
    current_domain: u64,
    /// General fast-path scratch slots used to spill values across
    /// phases (sender RIP/RFLAGS held until the user-stack write,
    /// `*Port` retained across the spinlock release, etc.).
    /// 8 slots = 64 bytes.
    fast_temp: [8]u64,
    /// Pointer to this core's `scheduler.PerCore` slot. Populated at
    /// init so the fast path can reach `last_fpu_owner` and
    /// `fpu_trap_armed` without a CPUID/APIC read followed by an array
    /// index — both would be MOV-CR0/MSR-class costs we can't afford
    /// inside the L4 path. Single deref, RIP-relative-free.
    per_core_ptr: u64,
    /// Snapshot of `cpu.pcid_enabled` written at init. The fast path
    /// can't reach the global `var` symbol RIP-relative from a naked
    /// fn without operand interpolation, so we cache it here and
    /// branch on the byte.
    pcid_enabled: u8,
    /// Pad out to a full page.
    _pad: [4096 - (14 * 8 + 8 + 1)]u8,
};

comptime {
    if (@sizeOf(SyscallScratch) != 4096) {
        @compileError("SyscallScratch must be exactly 4 KiB");
    }
}

/// SyscallScratch displacements pinned for the syscall-entry inline
/// asm. The slow-path prologue references these as immediate `gs:N`
/// memory operands rather than going through operand interpolation in
/// a naked stub, so layout drift on `SyscallScratch` must trip a
/// compile error here rather than silently corrupting the path. The
/// future L4 IPC fast path will share the same scratch layout, hence
/// the slot bookkeeping for `current_ec`, `current_domain`,
/// `per_core_ptr`, and the `fast_temp` band stays parked here for
/// when those slots become live again.
const Offsets = struct {
    const sc_kernel_rsp: usize = 0;
    const sc_user_rsp: usize = 8;
    const sc_user_rip: usize = 16;
    const sc_user_rflags: usize = 24;
    const sc_current_ec: usize = 32;
    const sc_current_domain: usize = 40;
    const sc_fast_temp_0: usize = 48;
    const sc_per_core_ptr: usize = 112;
    const sc_pcid_enabled: usize = 120;

    // cpu.Context iret-frame field offsets — referenced by the slow-path
    // Context-build literals (136/152/160).
    const ctx_rip: usize = @offsetOf(cpu.Context, "rip");
    const ctx_rflags: usize = @offsetOf(cpu.Context, "rflags");
    const ctx_rsp: usize = @offsetOf(cpu.Context, "rsp");
};

// Sanity-check the SyscallScratch displacements — extern struct, but
// even an extern layout flips on a Zig version bump if alignment
// rules ever change.
comptime {
    if (@offsetOf(SyscallScratch, "kernel_rsp") != Offsets.sc_kernel_rsp) @compileError("scratch.kernel_rsp drift");
    if (@offsetOf(SyscallScratch, "user_rsp") != Offsets.sc_user_rsp) @compileError("scratch.user_rsp drift");
    if (@offsetOf(SyscallScratch, "user_rip") != Offsets.sc_user_rip) @compileError("scratch.user_rip drift");
    if (@offsetOf(SyscallScratch, "user_rflags") != Offsets.sc_user_rflags) @compileError("scratch.user_rflags drift");
    if (@offsetOf(SyscallScratch, "current_ec") != Offsets.sc_current_ec) @compileError("scratch.current_ec drift");
    if (@offsetOf(SyscallScratch, "current_domain") != Offsets.sc_current_domain) @compileError("scratch.current_domain drift");
    if (@offsetOf(SyscallScratch, "fast_temp") != Offsets.sc_fast_temp_0) @compileError("scratch.fast_temp drift");
    if (@offsetOf(SyscallScratch, "per_core_ptr") != Offsets.sc_per_core_ptr) @compileError("scratch.per_core_ptr drift");
    if (@offsetOf(SyscallScratch, "pcid_enabled") != Offsets.sc_pcid_enabled) @compileError("scratch.pcid_enabled drift");
    if (Offsets.ctx_rip != 136) @compileError("cpu.Context.rip not at 136");
    if (Offsets.ctx_rflags != 152) @compileError("cpu.Context.rflags not at 152");
    if (Offsets.ctx_rsp != 160) @compileError("cpu.Context.rsp not at 160");
}

pub var per_cpu_scratch: [64]SyscallScratch align(4096) =
    [_]SyscallScratch{std.mem.zeroes(SyscallScratch)} ** 64;

/// Set KernelGsBase MSR for this core so SWAPGS can access per-CPU scratch.
/// Must be called on each core during init, after APIC is available and
/// after `cpu.enablePcid` has run (so the cached `pcid_enabled` flag is
/// authoritative for this core's lifetime).
pub fn initSyscallScratch(core_id: u64) void {
    const ia32_kernel_gs_base: u32 = 0xC0000102;
    const scratch = &per_cpu_scratch[core_id];
    scratch.per_core_ptr = @intFromPtr(&scheduler.core_states[core_id]);
    scratch.pcid_enabled = if (cpu.pcid_enabled) 1 else 0;
    cpu.wrmsr(ia32_kernel_gs_base, @intFromPtr(scratch));
}

/// Update per-CPU scratch kernel_rsp. Called from switchTo on every
/// context switch, mirroring the TSS.RSP0 update.
pub fn updateScratchKernelRsp(core_id: u64, kernel_rsp: u64) void {
    per_cpu_scratch[core_id].kernel_rsp = kernel_rsp;
}

/// Syscall dispatch — exported so the SYSCALL asm entry can call it.
/// Wraps the generic syscall.dispatch and writes the i64 return into
/// vreg 1 (rax). Spec §[syscall_abi] ABI:
///   - syscall_word lives at user vreg 0 = `[ctx.rsp + 0]`. SMAP gates
///     the read; STAC/CLAC bracket the user-stack load.
///   - args[0..13] = vregs 1..13, in spec order: rax, rbx, rdx, rbp,
///     rsi, rdi, r8, r9, r10, r12, r13, r14, r15. Stack-spilled vregs
///     14..127 are not collected here — handlers that need them read
///     them from `[ctx.rsp + (N-13)*8]` directly.
///   - return: i64 → ctx.regs.rax (vreg 1).
export fn syscallDispatch(ctx: *cpu.Context) void {
    const r = &ctx.regs;
    var args: [13]u64 = .{
        r.rax, r.rbx, r.rdx, r.rbp, r.rsi, r.rdi,
        r.r8,  r.r9,  r.r10, r.r12, r.r13, r.r14, r.r15,
    };
    var syscall_word: u64 = undefined;
    cpu.stac();
    syscall_word = @as(*const u64, @ptrFromInt(ctx.rsp)).*;
    cpu.clac();
    const caller = scheduler.currentEc() orelse @panic("syscall with no current EC");
    const ret = zag.syscall.dispatch.dispatch(caller, syscall_word, args[0..]);
    r.rax = @bitCast(ret);

    // If the dispatch suspended the calling EC (recv/suspend/futex
    // wait), `current_ec` was cleared on this core and `caller.state`
    // was retargeted to `.suspended_on_port` / `.futex_wait`. The asm
    // epilogue would otherwise iretq back to the parked user mode and
    // run the suspended EC. Switch to whatever's next (or idle); the
    // saved register restore in the asm trampoline never executes
    // because switchTo's `loadEcContextAndReturn` is `noreturn`.
    if (scheduler.core_states[apic.coreID()].current_ec == null) {
        scheduler.run();
    }
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
///
/// All syscalls currently route through the slow path: a 176-byte
/// `cpu.Context` save, followed by the generic `syscallDispatch`
/// trampoline into `zag.syscall.dispatch`, then iretq. The slow path
/// preserves vregs 1-13 (= rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10,
/// r12, r13, r14, r15) across the call by saving them into the
/// Context frame on entry and restoring them on exit, so any handler
/// (including suspend/recv/reply) that does not modify those slots
/// returns to userspace with them unchanged — matching the contract
/// the eventual L4-style IPC fast path is intended to preserve in
/// registers.
///
/// L4 IPC fast path — design intent (NOT YET WIRED): a future
/// implementation can short-circuit suspend/reply pairs that satisfy
/// the hot-path predicate (handle lookup hits, target waiter queued,
/// no attachments / no cap mismatches) by handling the rendezvous
/// inline in this naked stub, without touching vregs 1-13. The Phase
/// 1 prologue below already stashes user RSP/RIP/RFLAGS to per-CPU
/// scratch and peeks the syscall word from vreg 0; downstream phases
/// (handle resolve, port lock, PQ pop, CR3 + GS switch, lazy-FPU
/// policy, sysretq) require offsets pinned against the consuming
/// structs (CapabilityDomain handle tables, Port._gen_lock + waiters,
/// ExecutionContext.ctx + domain SlabRef) and a derivation-tree-aware
/// reply minting helper. Until those land the prologue falls straight
/// through to the slow path so suspend/reply executes via
/// `kernel/sched/port.zig` (`suspendEc`, `recv`, `reply`,
/// `replyTransfer`) — observable state matches what the fast path is
/// specified to produce per spec §[port], §[reply], §[event_state].
pub export fn syscallEntry() callconv(.naked) void {
    // Slow-path Context layout:
    //   [RSP+0..112]   r15..rax (15 GPRs, 120 bytes)
    //   [RSP+120,128]  int_num, err_code
    //   [RSP+136..168] iret frame (rip, cs, rflags, rsp, ss)
    asm volatile (
    // ═══════════════════════════════════════════════════════════════
    // PHASE 1 — common prologue: swapgs, stash user RSP/RIP/RFLAGS,
    // switch to kernel stack. Kept distinct from the slow-path body
    // because it is the shared entry the future fast path will branch
    // out of without paying the full Context save.
    // ═══════════════════════════════════════════════════════════════
        \\swapgs                              // GS.base → SyscallScratch
        \\movq %%rsp, %%gs:8                  // user_rsp
        \\movq %%rcx, %%gs:16                 // user_rip (rcx clobbered by SYSCALL)
        \\movq %%r11, %%gs:24                 // user_rflags (r11 ditto)
        \\movq %%gs:0, %%rsp                  // switch to kernel stack

    // ═══════════════════════════════════════════════════════════════
    // SLOW PATH — 176-byte Context save + dispatch + iretq.
    // Restores rcx and r11 from gs scratch first so the iret frame
    // sees the original SYSCALL-saved values, not whatever the
    // prologue may have spilled into those regs. Vregs 1-13 (rax,
    // rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15) are
    // saved into the Context on entry and restored on exit, so any
    // handler that leaves them alone returns them to userspace
    // unchanged — matching the L4 fast-path register-preservation
    // contract via the long route.
    // ═══════════════════════════════════════════════════════════════
        \\movq %%gs:16, %%rcx                 // restore user_rip
        \\movq %%gs:24, %%r11                 // restore user_rflags
        \\subq $176, %%rsp
        \\movq %%rbp, 80(%%rsp)
        \\movq %%gs:8, %%rbp
        \\movq %%rbp, 160(%%rsp)              // ctx.rsp = user RSP
        \\swapgs                              // restore user GS
        \\movq $0x1b, 168(%%rsp)              // ctx.ss
        \\movq %%r11, 152(%%rsp)              // ctx.rflags
        \\movq $0x23, 144(%%rsp)              // ctx.cs
        \\movq %%rcx, 136(%%rsp)              // ctx.rip
        \\movq $0,    128(%%rsp)              // ctx.err_code
        \\movq $0x80, 120(%%rsp)              // ctx.int_num
        \\movq %%rax, 112(%%rsp)
        \\movq %%rcx, 104(%%rsp)
        \\movq %%rdx, 96(%%rsp)
        \\movq %%rbx, 88(%%rsp)
        \\movq %%rsi, 72(%%rsp)
        \\movq %%rdi, 64(%%rsp)
        \\movq %%r8,  56(%%rsp)
        \\movq %%r9,  48(%%rsp)
        \\movq %%r10, 40(%%rsp)
        \\movq %%r11, 32(%%rsp)
        \\movq %%r12, 24(%%rsp)
        \\movq %%r13, 16(%%rsp)
        \\movq %%r14, 8(%%rsp)
        \\movq %%r15, 0(%%rsp)
        \\movq %%rsp, %%rdi
        \\call syscallDispatch
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
        \\addq $120, %%rsp
        \\addq $16, %%rsp
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

pub fn switchTo(ec: *ExecutionContext) void {
    const core_id = apic.coreID();
    const kstack = ec.kernel_stack.top.addr;
    gdt.coreTss(core_id).rsp0 = kstack;
    updateScratchKernelRsp(core_id, kstack);

    // self-alive: `ec` was selected by the scheduler for this core; its
    // domain is held live by the EC through the dispatch window (the
    // EC carries a SlabRef into the domain), so reading
    // `addr_space_root` / `addr_space_id` directly off the deref'd
    // pointer without re-locking the SlabRef is sound here.
    const dom = ec.domain.ptr;
    const new_root = dom.addr_space_root;
    if (new_root.addr != paging.getAddrSpaceRoot().addr) {
        paging.swapAddrSpace(new_root, dom.addr_space_id);
        std.debug.assert(paging.getAddrSpaceRoot().addr == new_root.addr);
    }

    const cid: u8 = @truncate(core_id);
    scheduler.core_states[cid].current_ec = ec;
    per_cpu_scratch[cid].current_ec = @intFromPtr(ec);
    per_cpu_scratch[cid].current_domain = @intFromPtr(dom);

    // Lazy FPU: TS should be clear iff `ec` is the current owner on
    // this core, set otherwise. Track the desired state and only touch
    // CR0 when it changes — MOV-to-CR0 vmexits under KVM at ~1k+
    // cycles per write, so skipping no-op writes is critical.
    //
    // Cross-core migration: if the EC's FP state lives in a different
    // core's regs, flush it out via IPI first so the trap handler
    // restores from the right buffer contents.
    //
    // Skipped under -Dlazy_fpu=false (eager baseline): the FPU regs
    // were already swapped in scheduler.switchToWithPmu and CR0.TS is
    // never armed, so no migration flush is needed either.
    if (comptime fpu.lazy_enabled) {
        scheduler.migrateFlush(ec);
        const desired_armed = (scheduler.core_states[cid].last_fpu_owner != ec);
        if (desired_armed != scheduler.core_states[cid].fpu_trap_armed) {
            if (desired_armed) cpu.fpuArmTrap() else cpu.fpuClearTrap();
            scheduler.core_states[cid].fpu_trap_armed = desired_armed;
        }
    }

    apic.endOfInterrupt();

    // lockdep: this asm `jmp interruptStubEpilogue` abandons the call stack
    // the IRQ-handler dispatcher (`dispatchInterrupt`) was using; its
    // `defer exitIrqContext` never executes. Re-balance the per-core IRQ
    // depth here so the counter doesn't drift upward each time an
    // IRQ-driven preemption produces a context switch. No-op when called
    // from non-IRQ paths (the depth is already zero there).
    sync_debug.resetIrqContextOnSwitch();

    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp interruptStubEpilogue
        :
        : [new_stack] "r" (@intFromPtr(ec.ctx)),
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

/// Spec §[event_state] vreg 2 — rbx on x86-64.
pub fn setEventSubcode(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rbx = value;
}

/// Spec §[event_state] vreg 3 — rdx on x86-64.
pub fn setEventAddr(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rdx = value;
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
    const entry = vector_table[ctx.int_num];
    if (entry.handler) |h| {
        // lockdep: an `external` vector is an asynchronous device/IPI/timer
        // interrupt — the CPU auto-masked IFLAG on entry (Intel SDM Vol 3A
        // §6.8.1) and the running thread was *interrupted*, not making a
        // synchronous call into the kernel. That is the only state in which
        // the IRQ-mode-mix detector should treat this acquire as "from an
        // IRQ handler." `exception` vectors (#PF, #GP, #UD, syscall stub at
        // 0x80) are synchronous — they execute on top of whatever IRQ-mode
        // discipline the interrupted code already chose, and must NOT count
        // as IRQ-handler context.
        const is_async_irq = entry.kind == .external;
        if (is_async_irq) sync_debug.enterIrqContext();
        defer if (is_async_irq) sync_debug.exitIrqContext();

        h(ctx);
        if (is_async_irq) {
            apic.endOfInterrupt();
        }
        return;
    }

    @panic("Unhandled interrupt!");
}
