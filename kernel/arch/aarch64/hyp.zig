//! AArch64 EL2 world-switch machinery (stub).
//!
//! Placeholder for the aarch64 hypervisor; the spec-v3 dispatch surface
//! only requires `installHypVectors` to exist. The full world-switch
//! machinery (HVC vector table, vmResume, host/guest save buffers,
//! vGIC LR plumbing, vtimer routing) was removed when the spec-v3
//! kernel cut over to the x86_64-only test runner. Restore from
//! git history when bringing aarch64 KVM back online.

/// Install the kernel's EL2 vector table at VBAR_EL2.
///
/// Stubbed for the spec-v3 branch — aarch64 KVM is not in the test
/// runner's critical path, and `vm.vmSupported()` returns false on
/// this branch, so the dispatch caller already short-circuits.
pub fn installHypVectors() void {}
