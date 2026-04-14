//! Shared EL2 hyp ABI constants.
//!
//! These values are referenced by both the UEFI bootloader's EL2 stub
//! (`bootloader/aarch64_el2_drop.zig`) and the kernel's world-switch
//! dispatcher (`kernel/arch/aarch64/vm.zig`). Keep them in one place to
//! guarantee both sides agree.

/// HVC immediate used by the kernel to ask the bootloader-installed EL2
/// stub to load VBAR_EL2 from X0 and ERET. Value is arbitrary but must
/// not collide with PSCI/SMCCC-defined immediates (those use HVC #0 with
/// a function-id register convention, whereas this path encodes the
/// selector in the instruction's imm16 so the EL2 stub can demux without
/// touching guest-facing argument registers). ARM ARM C5.6.103 (HVC)
/// places the immediate at ESR_EL2.ISS[15:0] on a sync-lower-EL trap.
pub const HVC_IMM_INSTALL_VBAR_EL2: u16 = 0xE112;
