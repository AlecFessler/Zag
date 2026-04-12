//! AArch64 hardware virtualization stubs.
//!
//! ARM virtualization uses EL2 (Hypervisor Exception Level), which is the
//! equivalent of x86's VMX/SVM. The design is fundamentally different:
//! instead of VMCS/VMCB control structures, ARM uses system register
//! trapping and stage-2 translation configured via EL2 registers.
//!
//! Key EL2 concepts (ARM ARM D1.4, D5.4):
//!   HCR_EL2:     Hypervisor Configuration Register — controls trapping,
//!                 stage-2 enable, interrupt routing.
//!   VTTBR_EL2:   stage-2 translation table base for the guest.
//!   ESR_EL2:     exception syndrome for traps to EL2.
//!   HPFAR_EL2:   IPA of a stage-2 fault (like EPT violation address on x86).
//!   VBAR_EL2:    exception vector base for EL2.
//!
//! VM entry/exit:
//!   Entry: ERET from EL2 to EL1 (guest) with HCR_EL2 configured.
//!   Exit:  exception taken to EL2 (configured traps, interrupts, stage-2 faults).
//!
//! This is future work — for now, vmSupported() returns false and all VM
//! operations are stubs. The dispatch layer's KVM syscalls return E_NOSYS.
//!
//! References:
//! - ARM ARM D1.4: Exception levels and Security states
//! - ARM ARM D5.4: Stage 2 translation
//! - ARM ARM D13.2.46: HCR_EL2

pub const GuestState = struct {};
pub const VmExitInfo = struct {};
pub const GuestInterrupt = struct {};
pub const GuestException = struct {};
pub const VmPolicy = struct {};
pub const FxsaveArea = [512]u8;

pub fn fxsaveInit() FxsaveArea {
    return .{0} ** 512;
}

pub fn vmInit() void {}
pub fn vmPerCoreInit() void {}

pub fn vmSupported() bool {
    return false;
}
