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

/// Hardware random number via RNDR (ARMv8.5-RNG).
/// ARM ARM C5.2.14: returns null if the TRNG entropy pool is exhausted
/// (NZCV.Z set on failure) or if the feature is not supported.
/// Feature detection: ID_AA64ISAR0_EL1 bits [63:60] (RNDR field) >= 1.
pub fn rndr() ?u64 {
    // TODO: check ID_AA64ISAR0_EL1.RNDR at init time and cache the result.
    // For now, return null (no hardware RNG) — the kernel falls back to a
    // software PRNG when getRandom() returns null.
    return null;
}
