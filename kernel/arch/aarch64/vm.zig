//! AArch64 VM dispatch surface (stub).
//!
//! The aarch64 KVM port is not in the spec-v3 critical path — the test
//! runner is x86_64-only — so this module exposes only the small dispatch
//! surface `arch/dispatch/vm.zig` and the boot handoff path require:
//! `vmInit`, `hyp_stub_installed`. Everything else (GuestState,
//! VmExitInfo, HCR_EL2 bits, hyp HVC ABI, etc.) was removed when the
//! spec-v3 cut-over deleted the in-tree aarch64 hypervisor scaffolding;
//! restore from git history when bringing aarch64 KVM back online.

/// Set true by the bootloader-driven boot handoff path when the kernel
/// arrived at EL2 (UEFI drops us at EL1 and leaves this false). Public
/// so `dispatch/vm.zig` can flip it before `installHypVectors`.
pub var hyp_stub_installed: bool = false;

/// Global VM subsystem init. Stubbed — the spec-v3 aarch64 port does
/// not advertise hardware virtualization, so `vmSupported`-style
/// callers in the dispatch layer naturally short-circuit.
pub fn vmInit() void {}
