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
