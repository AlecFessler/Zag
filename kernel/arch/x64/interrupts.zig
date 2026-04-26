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

/// Offsets pinned for the L4 fast-path inline asm. The asm references
/// these as immediate displacements (no operand interpolation in the
/// naked stub), so a layout drift on any referenced struct trips a
/// compile error rather than silently corrupting the path.
const Offsets = struct {
    // SyscallScratch (extern; deterministic).
    const sc_kernel_rsp: usize = 0;
    const sc_user_rsp: usize = 8;
    const sc_user_rip: usize = 16;
    const sc_user_rflags: usize = 24;
    const sc_current_ec: usize = 32;
    const sc_current_domain: usize = 40;
    const sc_fast_temp_0: usize = 48;
    const sc_fast_temp_1: usize = 56;
    const sc_fast_temp_2: usize = 64;
    const sc_fast_temp_3: usize = 72;
    const sc_fast_temp_4: usize = 80;
    const sc_fast_temp_5: usize = 88;
    const sc_fast_temp_6: usize = 96;
    const sc_fast_temp_7: usize = 104;
    const sc_per_core_ptr: usize = 112;
    const sc_pcid_enabled: usize = 120;

    // PerCore fields the fast path touches for lazy-FPU.
    const pc_current_ec: usize = @offsetOf(scheduler.PerCore, "current_ec");
    const pc_last_fpu_owner: usize = @offsetOf(scheduler.PerCore, "last_fpu_owner");
    const pc_fpu_trap_armed: usize = @offsetOf(scheduler.PerCore, "fpu_trap_armed");

    // ExecutionContext.ctx (pointer to saved cpu.Context iret frame).
    const ec_ctx: usize = @offsetOf(zag.sched.execution_context.ExecutionContext, "ctx");
    // ExecutionContext.domain — SlabRef(CapabilityDomain): { ptr, gen, _pad }.
    const ec_domain_ptr: usize = @offsetOf(zag.sched.execution_context.ExecutionContext, "domain");
    // ExecutionContext.next — ?SlabRef(EC). Bare pointer at +0 of the optional payload.
    const ec_next: usize = @offsetOf(zag.sched.execution_context.ExecutionContext, "next");

    // CapabilityDomain.addr_space_root (PAddr.addr is the raw u64).
    const dom_addr_space_root: usize = @offsetOf(zag.capdom.capability_domain.CapabilityDomain, "addr_space_root");
    const dom_addr_space_id: usize = @offsetOf(zag.capdom.capability_domain.CapabilityDomain, "addr_space_id");
    const dom_kernel_table: usize = @offsetOf(zag.capdom.capability_domain.CapabilityDomain, "kernel_table");
    const dom_user_table: usize = @offsetOf(zag.capdom.capability_domain.CapabilityDomain, "user_table");

    // KernelHandle (extern, 24 bytes): { ref: ErasedSlabRef, metadata: u64 }.
    // ErasedSlabRef = { ptr, gen, _pad } at offset 0.
    const kh_ref_ptr: usize = 0;
    const kh_ref_gen: usize = 8;
    const kh_size: usize = @sizeOf(zag.caps.capability.KernelHandle);

    // Capability (extern, 24 bytes): { word0, field0, field1 }.
    const cap_word0: usize = 0;
    const cap_size: usize = @sizeOf(zag.caps.capability.Capability);

    // Port._gen_lock starts at offset 0 (lock bit = bit 0 of GenLock.word).
    const port_gen_lock_word: usize = 0;
    const port_waiters: usize = @offsetOf(zag.sched.port.Port, "waiters");
    const port_waiter_kind: usize = @offsetOf(zag.sched.port.Port, "waiter_kind");

    // cpu.Context iret-frame field offsets.
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

    // Phase 2 stashes *receiver_EC at scratch+80 (slot fast_temp[4];
    // some code comments use a [5] label that's off-by-one from the
    // slot index but consistent with the asm). Phase 5 reads from
    // the same slot.
    if (Offsets.sc_fast_temp_4 != 80) @compileError("Phase 2/5 receiver slot expected at scratch+80");
}

// PerCore offsets the Phase 5 asm hardcodes (immediate displacements).
// PerCore is now an `extern struct` (see `scheduler.zig`) so declaration
// order is fixed and these literals are stable across Zig versions.
// The asserts catch any later field reorder before the asm reads from
// the wrong slot.
comptime {
    if (Offsets.pc_last_fpu_owner != 72) @compileError(
        "Phase 5 asm hardcodes PerCore.last_fpu_owner at +72; @offsetOf disagrees — update the asm or PerCore",
    );
    if (Offsets.pc_fpu_trap_armed != 80) @compileError(
        "Phase 5 asm hardcodes PerCore.fpu_trap_armed at +80; @offsetOf disagrees — update the asm or PerCore",
    );
}

// ExecutionContext.domain offset — Phase 5 walks receiver.domain.ptr
// via a single load. EC carries optional-of-extern-struct fields
// (`?SlabRef(...)`, `?Stack`) that block converting it to extern, so
// its layout is at the mercy of Zig's auto-reorder. The asm therefore
// substitutes `Offsets.ec_domain_ptr` as an `"i"` immediate operand at
// the Phase 5 publish-domain site; the assert below only sanity-checks
// that `domain` is 8-aligned — the actual numeric value is whatever
// Zig hands us.
comptime {
    if (Offsets.ec_domain_ptr % 8 != 0) @compileError(
        "EC.domain must be 8-aligned for the Phase 5 SlabRef.ptr load",
    );
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
/// L4-style IPC fast-path entry. Everything inlined; no `call`s in
/// the fast path so we don't burn cycles on SysV save/restore around
/// helpers. Vregs 1-13 (= rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10,
/// r12, r13, r14, r15) are the IPC payload and MUST stay pristine
/// through the entire suspend/reply path; only rcx, r11, rsp, and
/// gs-scratch / kstack-scratch are usable.
///
/// Phase structure (suspend with waiting receiver / reply):
///   1. Prologue: swapgs, stash user RSP/RIP/RFLAGS to gs scratch,
///      switch to kstack, peek vreg 0 from user stack, branch on
///      syscall_num.
///   2. Resolve handle, lock target, validate, dequeue receiver
///      (suspend) or load suspended sender (reply). All under sender's
///      CR3 — handle table is mapped read-only here.
///   3. Capture sender's TLS bases (rdfsbase / rdgsbase post-swapgs),
///      switch CR3 to receiver's domain (PCID-aware via
///      `cpu.pcid_enabled`).
///   4. Write event payload (syscall word + stack vregs) to receiver's
///      user stack. Vregs 1-13 stay in their GPRs untouched.
///   5. Re-establish kernel GS, publish current_ec/current_domain on
///      this core, apply lazy-FPU policy (arm/clear CR0.TS based on
///      receiver vs per-core last_fpu_owner), restore rcx (resume
///      RIP) / r11 (resume RFLAGS) / rsp (receiver user RSP) from
///      the kstack scratch frame, swapgs back to user GS, sysretq.
///      Vregs 1-13 remain pristine across the whole transition.
///
/// Slow path: any other syscall, or suspend with no waiting receiver,
/// or suspend with `read`/`write` cap mismatches we don't yet handle
/// in asm — falls through to the existing 176-byte Context save +
/// `syscallDispatch` + iretq.
///
/// Placeholder offset constants in Phase 2's handle-table walk are
/// marked TODO_OFF — they get pinned down as the consuming structs
/// (HandleTableEntry, EcQueue layout, Reply, Port internals,
/// CapabilityDomain) finish stabilizing. Pinned offsets used by
/// Phase 3 (PCID byte) and Phase 5 (PerCore lazy-FPU slots, EC.domain
/// SlabRef, SyscallScratch) are guarded by the `Offsets` table +
/// comptime asserts above.
pub export fn syscallEntry() callconv(.naked) void {
    // Slow-path Context layout:
    //   [RSP+0..112]   r15..rax (15 GPRs, 120 bytes)
    //   [RSP+120,128]  int_num, err_code
    //   [RSP+136..168] iret frame (rip, cs, rflags, rsp, ss)
    asm volatile (
    // ═══════════════════════════════════════════════════════════════
    // PHASE 1 — common prologue + syscall_num peek
    // ═══════════════════════════════════════════════════════════════
        \\swapgs                              // GS.base → SyscallScratch
        \\movq %%rsp, %%gs:8                  // user_rsp
        \\movq %%rcx, %%gs:16                 // user_rip (rcx clobbered by SYSCALL)
        \\movq %%r11, %%gs:24                 // user_rflags (r11 ditto)
        \\movq %%gs:0, %%rsp                  // switch to kernel stack

        // Read syscall_num from user vreg 0 = [user_rsp+0].
        // rcx is free (we stashed it). Bits 0-11 = syscall_num.
        \\movq %%gs:8, %%rcx
        \\stac                                // SMAP allow CPL3 access
        \\movq (%%rcx), %%rcx
        \\clac
        \\andl $0xFFF, %%ecx

        // TODO: SYS_SUSPEND, SYS_REPLY are placeholders until the new
        // syscall enum is defined.
        \\cmpl $0x10, %%ecx                   // SYS_SUSPEND (placeholder)
        \\je .L_fast_suspend
        \\cmpl $0x11, %%ecx                   // SYS_REPLY   (placeholder)
        \\je .L_fast_reply
        \\jmp .L_slow

    // ═══════════════════════════════════════════════════════════════
    // SLOW PATH — existing 176-byte Context save + dispatch + iretq.
    // We restore rcx and r11 from gs scratch first so the iret-frame
    // builder (which references them directly) sees the original
    // SYSCALL-saved values, not the syscall_num that overwrote rcx.
    // ═══════════════════════════════════════════════════════════════
        \\.L_slow:
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

    // ═══════════════════════════════════════════════════════════════
    // FAST SUSPEND — vreg 1 (rax) = target_handle,
    //                vreg 2 (rbx) = port_handle.
    // Both must remain untouched (they're the IPC payload to the
    // receiver). Free: rcx, r11; gs scratch slots fast_temp[0..7];
    // kstack scratch (subq).
    // ═══════════════════════════════════════════════════════════════
        \\.L_fast_suspend:

        // ── Resolve port handle → *Port via current domain's table ──
        // current_domain is at gs:40 (kept up-to-date by switchTo).
        \\movq %%gs:40, %%rcx                 // *CapabilityDomain
        // TODO_OFF: handle table base on CapabilityDomain. Use 16
        // as placeholder (after _gen_lock + handle_count or similar).
        \\movq 16(%%rcx), %%rcx               // *HandleTableEntry[]
        \\movq %%rbx, %%r11
        \\andl $0xFFF, %%r11d                 // handle_id
        // TODO_OFF: handle table entry size. Spec says 24 bytes (cap
        // word + field0 + field1) plus a kernel ptr+gen → ~40 bytes.
        // Using shift-by-5 (32) as placeholder until layout pinned.
        \\shlq $5, %%r11
        \\addq %%r11, %%rcx                   // rcx = &table[port_id]

        // Type-tag check: cap word bits 12-15 = type. TAG_PORT = 5
        // (placeholder). Bail to slow path on mismatch — dispatch
        // will return E_BADCAP cleanly.
        \\movw (%%rcx), %%r11w                // cap word low 16 bits
        \\andw $0xF000, %%r11w
        \\cmpw $0x5000, %%r11w                // (TAG_PORT << 12)
        \\jne .L_fast_bail

        // Capture expected slab gen for UAF check after lock.
        // TODO_OFF: kernel-side slot stores {*Port, gen}; gen offset
        // within entry. Using 32 as placeholder.
        \\movq 32(%%rcx), %%r11               // expected_gen
        \\movq %%r11, %%gs:48                 // → fast_temp[0]
        \\movq 24(%%rcx), %%rcx               // *Port (placeholder offset)
        \\movq %%rcx, %%gs:56                 // → fast_temp[1] (kept for unlock)

        // ── Inline spinlock acquire on Port._gen_lock ──
        // SpinLock is u32 at PORT_LOCK_OFF; 0=free, 1=held.
        // cmpxchg requires expected in rax. Spill rax (vreg 1) once
        // for the loop, restore after. PORT_LOCK_OFF placeholder = 0
        // (assume _gen_lock is the first field on Port).
        \\movq %%rax, %%gs:64                 // spill vreg 1 → fast_temp[2]
        \\.L_port_spin:
        \\xorl %%eax, %%eax                   // expected = 0
        \\movl $1, %%r11d                     // new = 1
        \\lock cmpxchgl %%r11d, 0(%%rcx)      // PORT_LOCK_OFF = 0 (placeholder)
        \\jz .L_port_acquired
        \\pause
        \\jmp .L_port_spin
        \\.L_port_acquired:
        \\movq %%gs:64, %%rax                 // restore vreg 1

        // Slab gen check — TODO_OFF: gen field within Port._gen_lock.
        // Using offset 8 as placeholder (after the lock word).
        \\movq 8(%%rcx), %%r11
        \\cmpq %%gs:48, %%r11
        \\jne .L_port_stale_unlock_bail

        // ── waiter_kind check ──
        // TODO_OFF: WaiterKind is the byte field after counters and
        // the EcQueue. Using 200 as placeholder (very rough). Values:
        // 0=none, 1=senders, 2=receivers (per WaiterKind enum order).
        \\cmpb $2, 200(%%rcx)                 // WK_RECEIVERS
        \\jne .L_no_receiver_unlock_bail

        // ── Inline PriorityQueue dequeue, 4 priority levels ──
        // Walk heads[3..0] (highest priority first). Heads array
        // assumed at PORT_HEADS_OFF = 100 (placeholder); each entry
        // is ?*EC = 8 bytes (8-byte ptr; null = 0). FIFO within
        // priority via tails[] which we update on pop.
        // (When PQ is upgraded to ?SlabRef(EC), entries become 16
        // bytes; this asm needs a follow-up.)
        \\.L_pq_pop:
        \\movq 124(%%rcx), %%r11              // heads[3] (realtime)
        \\testq %%r11, %%r11
        \\jne .L_pq_pop_lvl3
        \\movq 116(%%rcx), %%r11              // heads[2] (high)
        \\testq %%r11, %%r11
        \\jne .L_pq_pop_lvl2
        \\movq 108(%%rcx), %%r11              // heads[1] (normal)
        \\testq %%r11, %%r11
        \\jne .L_pq_pop_lvl1
        \\movq 100(%%rcx), %%r11              // heads[0] (idle)
        \\testq %%r11, %%r11
        \\jz .L_pq_empty_unlock_bail          // shouldn't reach if WK_RECEIVERS

        // Generic pop trampoline: the four lvl labels each set rcx to
        // the head-slot address before jumping here.
        // For the lvl0 fall-through case, set up rcx pointing at
        // heads[0] explicitly:
        \\addq $100, %%rcx                    // rcx → &heads[0]
        \\jmp .L_pq_pop_common

        \\.L_pq_pop_lvl3:
        \\addq $124, %%rcx
        \\jmp .L_pq_pop_common
        \\.L_pq_pop_lvl2:
        \\addq $116, %%rcx
        \\jmp .L_pq_pop_common
        \\.L_pq_pop_lvl1:
        \\addq $108, %%rcx
        \\jmp .L_pq_pop_common

        \\.L_pq_pop_common:
        // r11 = *EC of dequeued receiver, rcx = &heads[N].
        // Update head: heads[N] = r11->next.
        // EC_NEXT_OFF placeholder = 48 (after _gen_lock, ctx ptrs).
        // EC.next is currently `?SlabRef(EC)` — for the stub we treat
        // its first 8 bytes as the bare ptr (SlabRef.ptr). When the
        // PQ goes doubly-linked / SlabRef-aware this 16-byte case
        // gets handled.
        // Wait — the above is wrong; rework:
        // Now we need &heads[N] back. We trashed rcx. Stash &heads[N]
        // in fast_temp[4] before reading next, restructure required.
        // (Stub limitation; flagged for TDD iteration.)
        //
        // WHY this sequence: x86 has no mem→mem MOV, and both live
        // values (rcx=&heads[N], r11=*EC) must survive the head update
        // — r11 is reloaded by Phase-5's later `movq %gs:80,%r11` at
        // the publish-receiver-EC step (so we *can* clobber r11 here
        // as long as we publish it first). We publish *EC into fast_temp[4]
        // (gs:80) — the same slot Phase 2 / line 599 read from — then use
        // r11 as a one-register bounce: load r11 = (*EC).next.ptr, store
        // r11 → [rcx]. The duplicate `movq %r11,%gs:80` below is now
        // redundant but kept for symmetry with the reply path; harmless.
        // STILL MISSING (TDD iteration): EC.next is `?SlabRef(EC)` so
        // the literal 48 + treat-as-bare-ptr only works while the optional
        // payload happens to start at byte 0 of the field; PQ doubly-linked
        // (EC.prev), tails[N] update, and waiter_kind=.none on empty are
        // all unimplemented. See specv3.md Phase 5 priority-queue pop.
        \\movq %%r11, %%gs:80                 // publish *receiver_EC → fast_temp[4]
        \\movq %[ec_next](%%r11), %%r11       // r11 = (*EC).next.ptr (treat ?SlabRef payload@0)
        \\movq %%r11, 0(%%rcx)                // heads[N] = next
        // TODO: also walk EC.prev for doubly-linked + tails update +
        // waiter_kind = .none if queue now empty.

        // r11 = *receiver_EC. Stash for later phases.
        // (Already stashed above; this re-stash is dead but kept for now.)
        \\movq %%gs:80, %%r11                 // reload *receiver_EC into r11
        \\movq %%r11, %%gs:80                 // → fast_temp[5]

        // Restore *Port from fast_temp[1] for unlock.
        \\movq %%gs:56, %%rcx

        // ── Read receiver state from saved Context onto kstack ──
        // We're still on this EC's kstack. subq for scratch frame.
        // Layout (kstack scratch):
        //   [rsp+0]  receiver_resume_rip
        //   [rsp+8]  receiver_resume_rflags
        //   [rsp+16] receiver_user_rsp
        //   [rsp+24] receiver_cr3_root
        //   [rsp+32] receiver_pcid (16-bit)
        //   [rsp+40] receiver_syscall_word_return
        //   [rsp+48] sender_rip   (from gs:16)
        //   [rsp+56] sender_rflags(from gs:24)
        //   [rsp+64] sender_user_rsp(from gs:8)
        //   [rsp+72] sender_fs_base
        //   [rsp+80] sender_gs_base
        //   [rsp+88] receiver_fs_base
        //   [rsp+96] receiver_gs_base
        \\subq $112, %%rsp

        // EC_CTX_OFF placeholder = 16 (after _gen_lock).
        \\movq %%gs:80, %%r11                 // *receiver_EC
        \\movq 16(%%r11), %%rcx               // *Context (receiver's saved iret frame)
        // CTX_RIP/RFLAGS/USER_RSP offsets follow cpu.Context layout
        // above: rip=136, rflags=152, rsp=160.
        \\movq 136(%%rcx), %%r11
        \\movq %%r11, 0(%%rsp)                // receiver_resume_rip
        \\movq 152(%%rcx), %%r11
        \\movq %%r11, 8(%%rsp)                // receiver_resume_rflags
        \\movq 160(%%rcx), %%r11
        \\movq %%r11, 16(%%rsp)               // receiver_user_rsp

        // Receiver's domain → CR3 root + PCID.
        // EC_DOMAIN_OFF placeholder = 24.
        \\movq %%gs:80, %%r11
        \\movq 24(%%r11), %%rcx               // *receiver_domain
        // DOM_CR3_ROOT_OFF placeholder = 8, DOM_PCID_OFF = 16.
        \\movq 8(%%rcx), %%r11
        \\movq %%r11, 24(%%rsp)               // receiver_cr3_root
        \\movzwq 16(%%rcx), %%r11
        \\movq %%r11, 32(%%rsp)               // receiver_pcid

        // Ferry sender's stashed RIP/RFLAGS/RSP from gs to kstack
        // (we lose gs after swapgs in Phase 3).
        \\movq %%gs:16, %%r11
        \\movq %%r11, 48(%%rsp)               // sender_rip
        \\movq %%gs:24, %%r11
        \\movq %%r11, 56(%%rsp)               // sender_rflags
        \\movq %%gs:8,  %%r11
        \\movq %%r11, 64(%%rsp)               // sender_user_rsp

        // ── INLINE buildSuspendReturn ──
        // Build the syscall word return value for the receiver:
        //   bits 12-19: pair_count   = 0  (no attachments in fast path)
        //   bits 20-31: tstart       = 0
        //   bits 32-43: reply_handle_id = (mint reply slot in receiver)
        //   bits 44-48: event_type   = 4 (suspension)
        //
        // Reply handle minting (most complex inline op):
        //   1. Get *receiver_domain handle table
        //   2. Acquire receiver's domain table lock (similar
        //      cmpxchg-spin to port lock)
        //   3. Find a free slot via per-domain freelist:
        //      - Domain has `next_free: u16`; pop and follow chain
        //        encoded in unused entries
        //      - If freelist empty → bail to slow path so dispatch
        //        returns E_FULL
        //   4. Allocate Reply object from per-cpu Reply freelist
        //      (lock-free pop, cmpxchg on freelist head)
        //   5. Initialize Reply: back-pointer to current EC (the
        //      suspending sender, which is gs:32 = current_ec),
        //      port pointer, event_type
        //   6. Write handle table entry: cap word with type=reply
        //      (TAG_REPLY << 12) | xfer_bit_if_port_had_xfer | id,
        //      kernel ptr+gen for the Reply object
        //   7. Release receiver's domain table lock
        //   8. Compose syscall word: (slot_id << 32) | (4 << 44)
        //
        // For the stub: write a placeholder syscall word with
        // event_type=4 and slot_id=0. TDD pass fleshes out the
        // handle table + Reply slab inline expansions.
        // TODO_INLINE buildSuspendReturn — full inline expansion
        // pending stubs for HandleTableEntry, Reply, and the
        // receiver's domain freelist layout.
        \\movq $0x40000000000, %%r11          // event_type=4 << 44
        \\movq %%r11, 40(%%rsp)               // receiver_syscall_word_return

    // ═══════════════════════════════════════════════════════════════
    // PHASE 3 — capture sender TLS bases, switch CR3
    // ═══════════════════════════════════════════════════════════════
        // Snapshot the cached pcid_enabled byte from SyscallScratch
        // BEFORE swapgs (gs flips to user GS below and the byte is
        // unreachable without another swapgs). Stash low byte of rcx
        // into the high byte of kstack[32] alongside receiver_pcid so
        // the CR3-switch code can read both with a single qword load.
        // pcid_enabled lives at gs:120 (Offsets.sc_pcid_enabled).
        \\movzbq %%gs:120, %%rcx              // pcid_enabled flag (0/1)

        // Read sender's FS.base while GS is still kernel-scratch.
        \\rdfsbase %%r11
        \\movq %%r11, 72(%%rsp)               // sender_fs_base
        // Swap GS out so rdgsbase reads sender's user GS.base.
        \\swapgs
        \\rdgsbase %%r11
        \\movq %%r11, 80(%%rsp)               // sender_gs_base

        // TODO_LOCK: ideally the port lock release happens at the end
        // of Phase 2 — once the receiver has been popped, no further
        // mutation of the port queue is needed and the lock could be
        // dropped immediately. The current asm leaves it held until
        // teardown of the slow-path bail; pulling that release earlier
        // requires an additional fast_temp slot (the *Port pointer is
        // currently lost after the swapgs invalidates gs:56). Defer
        // until Phase 2 grows that scratch slot.

        // ── CR3 switch (PCID-aware) ──
        // pcid_enabled flag is in rcx (captured pre-swapgs above).
        // When PCID is on, OR the receiver_pcid into bits 0-11 of CR3
        // and set bit 63 ("preserve TLB" hint per Intel SDM Vol 3A
        // §4.10.4.1) so the cross-domain switch keeps the receiver's
        // existing TLB entries hot. When off, load CR3 raw (full
        // TLB flush — old/new domain entries collide otherwise).
        \\movq 24(%%rsp), %%r11               // receiver_cr3_root
        \\testb %%cl, %%cl
        \\jz .L_cr3_no_pcid
        \\orq 32(%%rsp), %%r11                // OR receiver_pcid (bits 0-11)
        \\btsq $63, %%r11                     // set CR3.NOFLUSH (bit 63)
        \\.L_cr3_no_pcid:
        \\movq %%r11, %%cr3

    // ═══════════════════════════════════════════════════════════════
    // PHASE 4 — write event payload to receiver's user stack
    // ═══════════════════════════════════════════════════════════════
        // CR3 = receiver; receiver's user stack mapped. SMAP allow.
        \\movq 16(%%rsp), %%rcx               // receiver_user_rsp
        \\stac
        \\movq 40(%%rsp), %%r11
        \\movq %%r11, 0(%%rcx)                // vreg 0 = syscall word return
        \\movq 48(%%rsp), %%r11
        \\movq %%r11, 8(%%rcx)                // vreg 14 = sender RIP
        \\movq 56(%%rsp), %%r11
        \\movq %%r11, 16(%%rcx)               // vreg 15 = sender RFLAGS
        \\movq 64(%%rsp), %%r11
        \\movq %%r11, 24(%%rcx)               // vreg 16 = sender RSP
        \\movq 72(%%rsp), %%r11
        \\movq %%r11, 32(%%rcx)               // vreg 17 = sender FS.base
        \\movq 80(%%rsp), %%r11
        \\movq %%r11, 40(%%rcx)               // vreg 18 = sender GS.base

        // TODO_ZERO: zero stack vregs 19..127 in receiver's user
        // stack (per event_type-specific upper bound; for a plain
        // suspension, no event-specific payload, so just zero the
        // band 48..1024 to avoid leaking kernel-side stack contents
        // across the boundary).

        // TODO_READCAP: if suspending EC handle's `read` cap = 0,
        // also zero vregs 1-13 (the GPRs) — would xor rax, rbx,
        // rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15 here.
        // For the stub we always pass through (assume read=1).
        \\clac

    // ═══════════════════════════════════════════════════════════════
    // PHASE 5 — receiver context restore + lazy FPU + sysret.
    //
    // State at entry:
    //   CR3 = receiver's (Phase 3), GS = sender user GS (Phase 3
    //   swapgs), RSP = kernel kstack with the 112-byte scratch frame,
    //   vregs 1-13 = sender payload (pristine — must remain so unless
    //   the suspending handle's `read` cap = 0, which we treat as the
    //   slow path for now). rcx and r11 are scratch.
    //
    // Steps:
    //   a. swapgs → GS = kernel SyscallScratch. We need scratch
    //      access to read the stashed receiver EC pointer
    //      (fast_temp[5]) and to publish current_ec / current_domain
    //      to the per-core slot.
    //   b. Set per-core SyscallScratch.current_ec / current_domain so
    //      switchTo-equivalent state is observable on this core.
    //   c. Lazy-FPU policy. Read per_core_ptr from scratch[112]; if
    //      receiver != last_fpu_owner, arm CR0.TS (mark
    //      fpu_trap_armed=1). Else clear CR0.TS (mark
    //      fpu_trap_armed=0). Skip the CR0 write entirely when
    //      fpu_trap_armed already matches the desired state — each
    //      MOV-to-CR0 is a vmexit under KVM. Cross-core FPU
    //      migration (last_fpu_core != current core, != null) is
    //      delegated to the slow path; here we only treat that as a
    //      fast-path bail through .L_fast_bail.
    //   d. Restore rcx / r11 / rsp from the kstack scratch frame
    //      (these hold the receiver's resume_rip / resume_rflags /
    //      user_rsp prepped in Phase 2). swapgs back to user GS,
    //      then sysretq.
    //
    // Receiver TLS (FS.base/GS.base) restoration is intentionally
    // deferred — `cpu.Context` does not yet carry FS/GS bases as
    // saved state, so the receiver runs with whatever the previous
    // context loaded. Userspace TLS-aware code re-establishes TLS
    // through `wr{fs,gs}base` itself; the FAST_TLS_TODO marks the
    // hook for when the EC iret frame grows TLS-base fields.
    //
    // Spec §[port].suspend / §[reply].reply observable state: this
    // matches sched/execution_context.zig:resumeFromReply (slow path)
    // — receiver state=running, current_ec=receiver, vregs 1-13 carry
    // the IPC payload, no FXSAVE/FXRSTOR happened (lazy).

        // (a) Re-establish kernel GS so we can reach SyscallScratch.
        \\swapgs

        // (b) Publish current_ec / current_domain on this core. We
        // stashed *receiver_EC at gs:80 in Phase 2. Pull it into r11
        // (scratch), then walk receiver.domain.ptr (SlabRef.ptr is
        // the first field of SlabRef) for the domain pointer.
        \\movq %%gs:80, %%r11                 // *receiver_EC
        \\movq %%r11, %%gs:32                 // current_ec = receiver
        // Read receiver.domain.ptr — SlabRef(CapabilityDomain) starts
        // at @offsetOf(EC,"domain"); SlabRef.ptr is the first field
        // (offset 0 within the SlabRef). EC is non-extern (carries
        // optional-of-struct fields that bar the conversion) so its
        // layout is whatever Zig's auto-reorder produces; the
        // displacement is supplied as an `"i"` operand resolved at
        // comptime from `Offsets.ec_domain_ptr`.
        \\movq %[ec_domain](%%r11), %%rcx
        \\movq %%rcx, %%gs:40                 // current_domain = receiver.domain.ptr

        // (c) Lazy-FPU policy. per_core_ptr is at scratch[112].
        \\movq %%gs:112, %%rcx                // *PerCore
        // Read PerCore.last_fpu_owner. PerCore is `extern struct`
        // (declaration order pinned), so the displacement is the
        // canonical `Offsets.pc_last_fpu_owner = 72`. The comptime
        // assert above guards against future reorders.
        \\movq 72(%%rcx), %%r11               // PerCore.last_fpu_owner
        \\cmpq %%r11, %%gs:80                 // == receiver?
        \\je .L_phase5_clear_ts

        // desired: CR0.TS armed (receiver != last_fpu_owner).
        // Check current fpu_trap_armed; skip the CR-write if already 1.
        \\cmpb $1, 80(%%rcx)                  // PerCore.fpu_trap_armed
        \\je .L_phase5_after_fpu
        \\movb $1, 80(%%rcx)                  // mark armed
        // Set CR0.TS (bit 3) — minimum-cost RMW.
        \\movq %%cr0, %%r11
        \\orq $0x8, %%r11
        \\movq %%r11, %%cr0
        \\jmp .L_phase5_after_fpu

        \\.L_phase5_clear_ts:
        // desired: CR0.TS clear (receiver IS the FPU owner).
        \\cmpb $0, 80(%%rcx)
        \\je .L_phase5_after_fpu
        \\movb $0, 80(%%rcx)
        // CLTS clears CR0.TS in one byte; cheaper than MOV-to-CR0.
        \\clts

        \\.L_phase5_after_fpu:

        // FAST_TLS_TODO: load receiver FS.base/GS.base via wrfsbase /
        // wrgsbase once cpu.Context grows fs_base/gs_base fields.
        // For now the receiver inherits whatever TLS state the prior
        // context left; userspace re-establishes TLS itself.

        // (d) Restore rcx (resume_rip), r11 (resume_rflags), rsp
        // (receiver_user_rsp) from the 112-byte kstack scratch frame.
        // Layout (set up in Phase 2):
        //   [rsp+0]  receiver_resume_rip
        //   [rsp+8]  receiver_resume_rflags
        //   [rsp+16] receiver_user_rsp
        \\movq 0(%%rsp), %%rcx                // user RIP for sysret
        \\movq 8(%%rsp), %%r11                // user RFLAGS for sysret
        \\movq 16(%%rsp), %%rsp               // restore receiver user RSP

        // swapgs out — receiver runs with its own user GS.base.
        \\swapgs
        \\sysretq

    // ═══════════════════════════════════════════════════════════════
    // FAST REPLY — vreg 1 (rax) = reply_handle.
    // Symmetrical to fast_suspend but the resolve targets a Reply
    // object (always has a suspended sender — no PQ pop), and the
    // delivery direction is reversed (resume sender, not receiver).
    // ═══════════════════════════════════════════════════════════════
        \\.L_fast_reply:
        // ── Resolve reply handle → *Reply ──
        \\movq %%gs:40, %%rcx                 // *CapabilityDomain
        \\movq 16(%%rcx), %%rcx               // *HandleTableEntry[]
        \\movq %%rax, %%r11
        \\andl $0xFFF, %%r11d                 // handle_id
        \\shlq $5, %%r11
        \\addq %%r11, %%rcx                   // &table[reply_id]
        \\movw (%%rcx), %%r11w
        \\andw $0xF000, %%r11w
        \\cmpw $0x6000, %%r11w                // (TAG_REPLY << 12)
        \\jne .L_fast_bail

        // *Reply contains back-pointer to suspended *EC (the sender).
        // TODO_OFF: REPLY_SENDER_OFF placeholder = 16.
        \\movq 24(%%rcx), %%rcx               // *Reply
        // Lock the Reply (similar inline cmpxchg pattern as port).
        // Validate not E_TERM/E_ABANDONED via state byte on Reply.
        // Pull *suspended_sender_EC.
        \\movq 16(%%rcx), %%r11               // *suspended_sender (placeholder)
        \\movq %%r11, %%gs:80                 // → fast_temp[5] (mirror suspend path)

        // From here, identical structure to suspend Phase 2 tail:
        // capture suspended_sender's saved Context (RIP/RFLAGS/RSP),
        // its domain CR3 root + PCID, then proceed through Phases 3-5.
        //
        // Two key differences vs suspend:
        //   - WRITE-cap gating: if originating EC handle's `write` = 1,
        //     receiver's CURRENT GPRs (the modifications) become
        //     sender's resumed state — meaning we leave vregs 1-13 in
        //     CPU and they pass through. If `write` = 0, we instead
        //     load sender's saved Context.regs into the GPRs before
        //     sysret, discarding the receiver's modifications.
        //   - Sender resumes from the suspend syscall — its return
        //     value goes in rax (= vreg 1 / first GPR), set to E_OK
        //     (or kernel-supplied) before sysret.
        //
        // For the stub, jump back into the common Phase 3-5 path.
        // TODO_REPLY_FULL: factor the common phase into a label both
        // suspend and reply branch into; for now stub trap.
        \\ud2

    // ═══════════════════════════════════════════════════════════════
    // BAIL labels — fall back to slow path on rare/error conditions.
    // ═══════════════════════════════════════════════════════════════
        \\.L_port_stale_unlock_bail:
        // Release port lock (PORT_LOCK_OFF=0 placeholder).
        \\movq %%gs:56, %%rcx
        \\movl $0, 0(%%rcx)
        \\jmp .L_fast_bail

        \\.L_no_receiver_unlock_bail:
        \\movq %%gs:56, %%rcx
        \\movl $0, 0(%%rcx)
        \\jmp .L_fast_bail

        \\.L_pq_empty_unlock_bail:
        \\movq %%gs:56, %%rcx
        \\movl $0, 0(%%rcx)
        \\jmp .L_fast_bail

        \\.L_fast_bail:
        // Common bail: reset to slow-path entry. Vregs 1-13 are
        // still pristine (we didn't touch them), so the slow path
        // sees the same state the user invoked with. We've added a
        // few gs scratch writes (negligible).
        \\jmp .L_slow
        :
        : [ec_domain] "i" (Offsets.ec_domain_ptr),
          [ec_next] "i" (Offsets.ec_next),
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
