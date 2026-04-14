//! Aarch64 virtual timer save/restore (ARM Generic Timer, virtual view).
//!
//! This is the aarch64 analogue of x64's per-vCPU TSC offset + APIC timer
//! plumbing, compressed into a single module because the ARM Generic
//! Timer exposes all of its virtual-view state in four sysregs:
//!
//!   CNTVOFF_EL2   Virtual counter offset. Subtracted from the physical
//!                 counter (CNTPCT_EL0) to produce the guest-visible
//!                 virtual counter (CNTVCT_EL0). Per-VM in principle but
//!                 we program it per-vCPU entry for simplicity.
//!                 ARM ARM D13.11.9.
//!
//!   CNTV_CTL_EL0  Virtual timer control. Bit 0 ENABLE, bit 1 IMASK,
//!                 bit 2 ISTATUS. ARM ARM D13.11.17.
//!
//!   CNTV_CVAL_EL0 Virtual timer compare value. 64-bit absolute compare
//!                 against CNTVCT_EL0; timer fires when CNTVCT ≥ CVAL.
//!                 ARM ARM D13.11.19.
//!
//!   CNTKCTL_EL1   Kernel access control for EL0 counter access. Linux
//!                 guests program this to 0x3 (EL0PCTEN | EL0VCTEN) so
//!                 userspace vDSO can read the counters without trapping.
//!                 ARM ARM D13.11.26.
//!
//! The virtual timer fires a PPI (INTID 27, ARM ARM D11.1.4 / GICv3
//! §2.2.3). When the kernel host-side timer subsystem detects the
//! virtual timer expiring for a non-running vCPU, it should call
//! `vgic.injectInterrupt` with INTID=27 to wake the guest. That wiring
//! is not in place for M5 — see TODO below.
//!
//! References:
//!   - docs/aarch64/DDI0487_arm_arm.pdf D13.11 "The Generic Timer"
//!   - docs/aarch64/IHI0069_gicv3.pdf §2.2.3 "Special interrupt numbers"
//!     for the PPI27 assignment.
//!   - Linux arch/arm64/kvm/arch_timer.c kvm_timer_vcpu_{load,put}.

const std = @import("std");
const zag = @import("zag");

const vm_hw = zag.arch.aarch64.vm;

/// Virtual timer PPI per ARM ARM D11.1.4 / GICv3 §2.2.3.
pub const VTIMER_PPI_INTID: u32 = 27;

/// Per-vCPU virtual timer save area. Written by `saveGuest` on exit
/// and read by `loadGuest` on the next entry.
///
/// We snapshot CNTKCTL_EL1 as well because the host's own EL1 code can
/// use CNTKCTL (for EL0 counter access in the kernel's vDSO path), so
/// it has to be swapped atomically with the other per-context state.
/// Per-vCPU virtual timer shadow. `extern struct` with a fixed field
/// order because `hvc_vtimer_load_guest` / `hvc_vtimer_save_guest` in
/// `arch/aarch64/vm.zig` index into this struct by hardcoded byte
/// offsets. The comptime asserts below pin the layout so any future
/// field reordering breaks compilation instead of silently scrambling
/// EL2 sysreg programming.
pub const VtimerState = extern struct {
    /// CNTVOFF_EL2 — applied to the physical counter to yield CNTVCT_EL0
    /// inside the guest. We freeze the guest counter at 0 on first
    /// entry by taking a snapshot of the current CNTPCT_EL0 as the
    /// offset; subsequent runs preserve whatever offset the guest was
    /// observing when it last exited. ARM ARM D13.11.9.
    cntvoff_el2: u64 = 0,

    /// CNTV_CTL_EL0 (ENABLE / IMASK / ISTATUS). ARM ARM D13.11.17.
    cntv_ctl_el0: u64 = 0,

    /// CNTV_CVAL_EL0 — next fire point. ARM ARM D13.11.19.
    cntv_cval_el0: u64 = 0,

    /// CNTKCTL_EL1 — EL0 counter access control. Default grants the
    /// guest EL0 permission to read both physical and virtual counters
    /// (EL0PCTEN | EL0VCTEN). Linux KVM does the same in
    /// arch_timer.c timer_set_guest_cntkctl. ARM ARM D13.11.26.
    cntkctl_el1: u64 = 0x3,

    /// Whether this vCPU has ever been entered. First-entry path
    /// takes a snapshot of CNTPCT_EL0 as the initial CNTVOFF_EL2 so
    /// the guest's virtual counter starts at zero. `u64` rather than
    /// `bool` because the EL2 stub tests it with `cbnz x3, ...` and
    /// the struct must be `extern` (which disallows `bool` fields in
    /// a stable ABI position).
    primed: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(VtimerState, "cntvoff_el2") == 0x00);
    std.debug.assert(@offsetOf(VtimerState, "cntv_ctl_el0") == 0x08);
    std.debug.assert(@offsetOf(VtimerState, "cntv_cval_el0") == 0x10);
    std.debug.assert(@offsetOf(VtimerState, "cntkctl_el1") == 0x18);
    std.debug.assert(@offsetOf(VtimerState, "primed") == 0x20);
}

/// Initialize a vtimer save area. Called from `vcpu.create`.
pub fn initVcpu(state: *VtimerState) void {
    state.* = .{};
}

/// Load the per-vCPU virtual timer state into the hardware sysregs
/// just before world-switch entry.
///
/// Called from the vCPU run loop at EL1 (see `kvm/vcpu.zig
/// vcpuEntryPoint`). CNTVOFF_EL2 is EL2-only (ARM ARM D13.11.9) and
/// an EL1 `msr cntvoff_el2, ...` would trap as an undefined
/// instruction, so the actual sysreg programming is forwarded to the
/// `hvc_vtimer_load_guest` stub which runs at EL2 and indexes this
/// struct by the offsets pinned above. The stub also seeds `cntvoff`
/// from CNTPCT_EL0 on first entry (`primed == 0`).
///
/// Reference: Linux arch/arm64/kvm/arch_timer.c kvm_timer_vcpu_load.
pub fn loadGuest(state: *VtimerState) void {
    _ = vm_hw.hypCall(.vtimer_load_guest, @intFromPtr(state));
}

/// Save the hardware virtual timer sysregs back into the per-vCPU
/// save area just after world-switch exit.
///
/// Forwarded through `hvc_vtimer_save_guest`: reads CNTV_CTL_EL0 /
/// CNTV_CVAL_EL0 / CNTKCTL_EL1 into the shadow and then disables the
/// virtual timer line (CNTV_CTL_EL0 ← IMASK=1 | ENABLE=0) so a
/// post-exit match cannot fire into the host. CNTVOFF_EL2 is not
/// read back — it is EL2-only and our shadow is authoritative.
/// ARM ARM D13.11.17.
///
/// Reference: Linux arch_timer.c kvm_timer_vcpu_put.
pub fn saveGuest(state: *VtimerState) void {
    _ = vm_hw.hypCall(.vtimer_save_guest, @intFromPtr(state));

    // TODO(m5-follow-up): when CNTV_CTL_EL0.ISTATUS is set at exit
    // (timer has fired while guest was running) we should re-inject
    // VTIMER_PPI_INTID into the vGIC here so the guest observes the
    // interrupt on the next entry. Requires the vgic.injectInterrupt
    // path to accept a SGI/PPI from kernel context — tracked as a
    // follow-up because the host timer subsystem also has to kick
    // vCPUs for expiry events of non-running guests.
}

comptime {
    _ = zag;
}
