//! AArch64 CPU primitives and system register access.
//!
//! Provides low-level CPU operations: system register read/write via MRS/MSR,
//! feature detection via ID registers, memory barriers, and instruction helpers.
//!
//! Key responsibilities:
//! - halt(): WFI (Wait For Interrupt) — equivalent of x86 HLT.
//! - enableInterrupts() / saveAndDisableInterrupts() / restoreInterrupts():
//!   DAIF flag manipulation (PSTATE.{D,A,I,F} mask bits).
//!   ARM ARM D1.7.3 "Interrupt masking" — clear/set PSTATE.I via MSR DAIFClr/DAIFSet.
//! - PAN (Privileged Access Never) toggle for userAccessBegin/End:
//!   ARM ARM D5.4.6 — set/clear PSTATE.PAN to control kernel access to user pages.
//! - RNDR instruction for hardware random number generation:
//!   ARM ARM C5.2.14 (ARMv8.5-RNG) — reads from a TRNG; returns NZCV.Z=1 on failure.
//! - Feature detection via ID_AA64ISAR0_EL1, ID_AA64MMFR1_EL1, etc.
//! - Memory/instruction barriers: DMB, DSB, ISB.
//!
//! References:
//! - ARM ARM DDI 0487 (Architecture Reference Manual for A-profile)
//! - ARM ARM C5.2: AArch64 System Instructions
//! - ARM ARM D1.7: Interrupt masking

const std = @import("std");
const builtin = @import("builtin");
const zag = @import("zag");

const gic = zag.arch.aarch64.gic;
const interrupts = zag.arch.aarch64.interrupts;

/// True when the target CPU advertises the ARMv8.1 PAN (Privileged
/// Access Never) feature. Cortex-A72 is ARMv8.0 and lacks PAN; the
/// `msr pan, #imm` mnemonic is UNDEFINED there and must not execute.
const has_pan = std.Target.aarch64.featureSetHas(
    builtin.cpu.features,
    .pan,
);

pub fn halt() noreturn {
    while (true) {
        asm volatile ("wfi");
    }
}

pub fn enableInterrupts() void {
    // DAIFClr: clear PSTATE.I (bit 1) to unmask IRQs.
    // ARM ARM C5.2.3: MSR DAIFClr, #imm
    asm volatile ("msr daifclr, #0x2");
}

pub fn saveAndDisableInterrupts() u64 {
    // Read DAIF, then set PSTATE.I to mask IRQs.
    var daif: u64 = undefined;
    asm volatile ("mrs %[daif], daif"
        : [daif] "=r" (daif),
    );
    asm volatile ("msr daifset, #0x2");
    return daif;
}

pub fn restoreInterrupts(state: u64) void {
    asm volatile ("msr daif, %[state]"
        :
        : [state] "r" (state),
    );
}

/// Disable PAN — allow kernel to access user pages.
/// ARM ARM D5.4.6: MSR PAN, #0 clears PSTATE.PAN.
/// No-op on ARMv8.0 targets without PAN (kernel always can access
/// user pages, no SMAP-equivalent enforcement).
pub inline fn panDisable() void {
    if (has_pan) asm volatile ("msr pan, #0");
}

/// Enable PAN — block kernel access to user pages.
/// ARM ARM D5.4.6: MSR PAN, #1 sets PSTATE.PAN.
/// No-op on ARMv8.0 targets without PAN.
pub inline fn panEnable() void {
    if (has_pan) asm volatile ("msr pan, #1");
}

/// Read the virtual counter (CNTVCT_EL0).
/// ARM ARM D11.2.3: monotonically incrementing at CNTFRQ_EL0 Hz.
/// Equivalent of x86 RDTSC — a high-resolution timestamp source.
pub inline fn readCntvct() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], cntvct_el0"
        : [val] "=r" (val),
    );
    return val;
}

/// Software PRNG state used as a fallback when ARMv8.5-RNG is unavailable.
/// Seeded lazily from CNTVCT_EL0 on first use; subsequently advanced by
/// xorshift64* with additional mixing from the virtual counter so that
/// successive calls within a tight loop still diverge.
/// Not cryptographically strong — adequate for the behavioural contract
/// of `getrandom` (non-zero bytes, non-blocking) on platforms lacking a
/// true hardware TRNG.
var prng_state: u64 = 0;

fn prngNext() u64 {
    if (prng_state == 0) {
        // Lazy seed: mix CNTVCT twice spread across a handful of cycles.
        const s0 = readCntvct();
        const s1 = readCntvct();
        prng_state = (s0 ^ (s1 << 13) ^ 0x9E3779B97F4A7C15);
        if (prng_state == 0) prng_state = 0x9E3779B97F4A7C15;
    }
    var x = prng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    prng_state = x;
    // Mix with current CNTVCT to resist accidental state replay if the
    // state word is ever observed externally.
    return (x *% 0x2545F4914F6CDD1D) ^ readCntvct();
}

/// Hardware random number via RNDR (ARMv8.5-RNG), falling back to a
/// software PRNG seeded from CNTVCT_EL0 on cores that lack the feature.
/// ARM ARM C5.2.14: RNDR returns NZCV.Z=1 on entropy exhaustion.
/// Feature detection: ID_AA64ISAR0_EL1 bits [63:60] (RNDR field) >= 1.
/// The Cortex-A72/A76 cores Zag currently targets do not implement RNG,
/// so the PRNG path is the common case on our reference hardware.
pub fn rndr() ?u64 {
    // Feature detection: ID_AA64ISAR0_EL1 bits [63:60] (RNDR field). A
    // value >= 1 indicates that the RNDR/RNDRRS system registers are
    // implemented. On hosts without the feature, MRS RNDR traps as
    // UNDEFINED, so we must gate every access on this probe.
    var isar0: u64 = undefined;
    asm volatile ("mrs %[v], ID_AA64ISAR0_EL1"
        : [v] "=r" (isar0),
    );
    if (((isar0 >> 60) & 0xF) != 0) {
        // MRS Xt, RNDR — reads 64 bits from the TRNG. On success
        // NZCV.Z=0 and Xt holds a random value; on entropy exhaustion
        // NZCV.Z=1 and Xt is zero. Read NZCV via MRS to determine
        // success (Zig aarch64 inline asm does not expose flag-output
        // clobbers reliably). ARM ARM C5.2.14.
        var val: u64 = undefined;
        var nzcv: u64 = undefined;
        asm volatile (
            \\mrs %[val], S3_3_C2_C4_0
            \\mrs %[nzcv], nzcv
            : [val] "=r" (val),
              [nzcv] "=r" (nzcv),
            :
            : .{ .nzcv = true });
        // NZCV bit 30 is Z. If Z == 1 the TRNG was exhausted this cycle
        // — fall through to the software PRNG rather than returning
        // E_AGAIN, so userspace `getrandom` still makes forward progress
        // on platforms where RNDR occasionally fails.
        if ((nzcv & (1 << 30)) == 0) return val;
    }
    return prngNext();
}

// ── Lazy FPU primitives ────────────────────────────────────────────
//
// FPSIMD register file layout in `Thread.fpu_state` (576 bytes, only
// the first 528 used; the rest is forward-compat headroom):
//   [0   ..512)  V0..V31      — 32 × 128-bit vector regs (16B each)
//   [512..520)   FPCR         — Floating-Point Control Register
//   [520..528)   FPSR         — Floating-Point Status Register
//
// The kernel itself is built without NEON/fp_armv8 (see build.zig
// cpu_features_sub) so it never emits FPSIMD instructions and never
// disturbs userspace V regs. CPACR_EL1.FPEN is held at 0b01 (trap EL0
// only) when the local thread isn't the FPU owner on this core, and
// 0b11 (no trap) when it is. ARM ARM D13.2.30.

/// Initialise an FPU buffer to the architectural reset state for a
/// brand-new thread. Per ARM ARM B4.1.36, FPCR resets to 0 (round to
/// nearest, no exceptions enabled, default NaN off, FZ off) and FPSR
/// resets to 0 (no sticky exception flags). All zeros suffices.
pub fn fpuStateInit(area: *[576]u8) void {
    @memset(area, 0);
}

/// Save V0-V31, FPCR, FPSR into `area`. The kernel has no NEON regs
/// of its own to preserve (built without fp-armv8/neon — see
/// build.zig cpu_features_sub), so this captures purely userspace
/// state. The `.arch_extension fp+neon` directive locally re-enables
/// the assembler so it accepts the SIMD/FP instructions; the kernel
/// at large still can't emit them.
pub fn fpuSave(area: *[576]u8) void {
    asm volatile (
        \\stp  q0,  q1,  [%[a], #0]
        \\stp  q2,  q3,  [%[a], #32]
        \\stp  q4,  q5,  [%[a], #64]
        \\stp  q6,  q7,  [%[a], #96]
        \\stp  q8,  q9,  [%[a], #128]
        \\stp  q10, q11, [%[a], #160]
        \\stp  q12, q13, [%[a], #192]
        \\stp  q14, q15, [%[a], #224]
        \\stp  q16, q17, [%[a], #256]
        \\stp  q18, q19, [%[a], #288]
        \\stp  q20, q21, [%[a], #320]
        \\stp  q22, q23, [%[a], #352]
        \\stp  q24, q25, [%[a], #384]
        \\stp  q26, q27, [%[a], #416]
        \\stp  q28, q29, [%[a], #448]
        \\stp  q30, q31, [%[a], #480]
        \\mrs  x0, fpcr
        \\str  x0, [%[a], #512]
        \\mrs  x0, fpsr
        \\str  x0, [%[a], #520]
        :
        : [a] "r" (area),
        : .{ .memory = true, .x0 = true });
}

/// Restore V0-V31, FPCR, FPSR from `area`. Inverse of `fpuSave`.
pub fn fpuRestore(area: *[576]u8) void {
    asm volatile (
        \\ldp  q0,  q1,  [%[a], #0]
        \\ldp  q2,  q3,  [%[a], #32]
        \\ldp  q4,  q5,  [%[a], #64]
        \\ldp  q6,  q7,  [%[a], #96]
        \\ldp  q8,  q9,  [%[a], #128]
        \\ldp  q10, q11, [%[a], #160]
        \\ldp  q12, q13, [%[a], #192]
        \\ldp  q14, q15, [%[a], #224]
        \\ldp  q16, q17, [%[a], #256]
        \\ldp  q18, q19, [%[a], #288]
        \\ldp  q20, q21, [%[a], #320]
        \\ldp  q22, q23, [%[a], #352]
        \\ldp  q24, q25, [%[a], #384]
        \\ldp  q26, q27, [%[a], #416]
        \\ldp  q28, q29, [%[a], #448]
        \\ldp  q30, q31, [%[a], #480]
        \\ldr  x0, [%[a], #512]
        \\msr  fpcr, x0
        \\ldr  x0, [%[a], #520]
        \\msr  fpsr, x0
        :
        : [a] "r" (area),
        : .{ .memory = true, .x0 = true });
}

/// Set CPACR_EL1.FPEN bits [21:20] = 0b11 — no FP/SIMD trap at any EL.
/// Called at the end of the lazy-FPU trap handler.
/// ARM ARM D13.2.30.
pub fn fpuClearTrap() void {
    var cpacr: u64 = undefined;
    asm volatile ("mrs %[v], cpacr_el1"
        : [v] "=r" (cpacr),
    );
    cpacr |= (@as(u64, 0b11) << 20);
    asm volatile ("msr cpacr_el1, %[v]"
        :
        : [v] "r" (cpacr),
    );
    asm volatile ("isb" ::: .{ .memory = true });
}

/// Set CPACR_EL1.FPEN bits [21:20] = 0b01 — trap EL0 FP/SIMD only.
/// EL1 (kernel) FP access still doesn't trap, but the kernel doesn't
/// emit any FP instructions so this is irrelevant. Called from
/// switchTo when the new thread isn't the current FPU owner.
/// ARM ARM D13.2.30.
pub fn fpuArmTrap() void {
    var cpacr: u64 = undefined;
    asm volatile ("mrs %[v], cpacr_el1"
        : [v] "=r" (cpacr),
    );
    // Clear bits [21:20] then set bit 20 (= 0b01).
    cpacr &= ~(@as(u64, 0b11) << 20);
    cpacr |= (@as(u64, 0b01) << 20);
    asm volatile ("msr cpacr_el1, %[v]"
        :
        : [v] "r" (cpacr),
    );
    asm volatile ("isb" ::: .{ .memory = true });
}

/// Flush a thread's FP regs from a remote core via SGI 2.
/// See `kernel/arch/aarch64/exceptions.zig` for the receiver.
pub fn fpuFlushIpi(target_core: u8, thread: anytype) void {
    interrupts.fpu_flush_mailbox[target_core].requestThread(thread);
    gic.sendIpiToCore(target_core, 2);
    interrupts.fpu_flush_mailbox[target_core].waitDone();
}
