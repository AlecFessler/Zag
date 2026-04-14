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

const zag = @import("zag");

/// Virtual timer PPI per ARM ARM D11.1.4 / GICv3 §2.2.3.
pub const VTIMER_PPI_INTID: u32 = 27;

/// Per-vCPU virtual timer save area. Written by `saveGuest` on exit
/// and read by `loadGuest` on the next entry.
///
/// We snapshot CNTKCTL_EL1 as well because the host's own EL1 code can
/// use CNTKCTL (for EL0 counter access in the kernel's vDSO path), so
/// it has to be swapped atomically with the other per-context state.
pub const VtimerState = struct {
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
    /// the guest's virtual counter starts at zero.
    primed: bool = false,
};

/// Initialize a vtimer save area. Called from `vcpu.create`.
pub fn initVcpu(state: *VtimerState) void {
    state.* = .{};
}

/// Load the per-vCPU virtual timer state into the hardware sysregs
/// just before world-switch entry.
///
/// Called from the vCPU run loop (see `kvm/vcpu.zig vcpuEntryPoint`)
/// at EL2 — the CNT*_EL0 registers are accessible from EL1 but
/// CNTVOFF_EL2 is EL2-only (ARM ARM D13.11.9). This module is only
/// invoked from the world-switch wrapper, which runs inside the
/// hypervisor dispatcher path where EL2 access is legal.
///
/// Reference: Linux arch/arm64/kvm/arch_timer.c kvm_timer_vcpu_load.
pub fn loadGuest(state: *VtimerState) void {
    if (!state.primed) {
        // First entry: snapshot CNTPCT_EL0 as the starting virtual
        // counter offset so the guest sees CNTVCT_EL0 == 0 on boot.
        // ARM ARM D13.11.9 — CNTVCT_EL0 = CNTPCT_EL0 - CNTVOFF_EL2.
        state.cntvoff_el2 = readCntpct();
        state.primed = true;
    }
    writeCntvoffEl2(state.cntvoff_el2);
    writeCntkctlEl1(state.cntkctl_el1);
    writeCntvCvalEl0(state.cntv_cval_el0);
    // CNT*_CTL_EL0 last so the guest's IMASK/ENABLE are observed
    // with the new CVAL already in place (ARM ARM D13.11.17 ISTATUS
    // re-evaluates on every read).
    writeCntvCtlEl0(state.cntv_ctl_el0);
}

/// Save the hardware virtual timer sysregs back into the per-vCPU
/// save area just after world-switch exit.
///
/// Reference: Linux arch_timer.c kvm_timer_vcpu_put.
pub fn saveGuest(state: *VtimerState) void {
    state.cntv_ctl_el0 = readCntvCtlEl0();
    state.cntv_cval_el0 = readCntvCvalEl0();
    // CNTVOFF_EL2 cannot be changed by the guest (it's EL2-only) so
    // we do not need to read it back — our shadow is authoritative.
    // CNTKCTL_EL1 CAN be written by the guest at EL1, so snapshot it.
    state.cntkctl_el1 = readCntkctlEl1();

    // Disable the hardware virtual timer before returning to host
    // context so a post-exit CNTV match cannot fire into the host.
    // Linux does the same: timer_save_state masks the line with a
    // write of ENABLE=0 | IMASK=1. ARM ARM D13.11.17.
    writeCntvCtlEl0(2);

    // TODO(m5-follow-up): when CNTV_CTL_EL0.ISTATUS is set at exit
    // (timer has fired while guest was running) we should re-inject
    // VTIMER_PPI_INTID into the vGIC here so the guest observes the
    // interrupt on the next entry. Requires the vgic.injectInterrupt
    // path to accept a SGI/PPI from kernel context — tracked as a
    // follow-up because the host timer subsystem also has to kick
    // vCPUs for expiry events of non-running guests.
}

// ===========================================================================
// Sysreg accessors
// ===========================================================================
//
// All CNT*_EL0 registers are readable/writable from EL1; CNTVOFF_EL2 is
// EL2-only. This module is only invoked from the world-switch dispatcher
// path which runs at EL2, so the EL2-level msr/mrs below are legal.

inline fn readCntpct() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], cntpct_el0"
        : [v] "=r" (v),
    );
    return v;
}

inline fn writeCntvoffEl2(value: u64) void {
    asm volatile ("msr cntvoff_el2, %[v]"
        :
        : [v] "r" (value),
    );
}

inline fn writeCntkctlEl1(value: u64) void {
    asm volatile ("msr cntkctl_el1, %[v]"
        :
        : [v] "r" (value),
    );
}

inline fn readCntkctlEl1() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], cntkctl_el1"
        : [v] "=r" (v),
    );
    return v;
}

inline fn writeCntvCtlEl0(value: u64) void {
    asm volatile ("msr cntv_ctl_el0, %[v]"
        :
        : [v] "r" (value),
    );
}

inline fn readCntvCtlEl0() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], cntv_ctl_el0"
        : [v] "=r" (v),
    );
    return v;
}

inline fn writeCntvCvalEl0(value: u64) void {
    asm volatile ("msr cntv_cval_el0, %[v]"
        :
        : [v] "r" (value),
    );
}

inline fn readCntvCvalEl0() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], cntv_cval_el0"
        : [v] "=r" (v),
    );
    return v;
}

comptime {
    _ = zag;
}
