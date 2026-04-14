//! PSCI (Power State Coordination Interface) dispatch stub.
//!
//! Arm DEN 0022F "Power State Coordination Interface Platform Design
//! Document" defines an SMCCC-compatible function namespace in
//! 0x8400_0000..0x8400_001F (SMC32) and 0xC400_0000..0xC400_001F (SMC64)
//! that guests use for CPU on/off, system reset, and version discovery.
//!
//! Linux's arm64 boot protocol requires the firmware to respond to PSCI
//! calls to bring up secondary CPUs (see Documentation/arm64/booting.rst
//! §"CPU Power States"), so a Zag guest running Linux must eventually see
//! real implementations here.
//!
//! This module is intentionally a thin dispatcher for Milestone M2: it
//! decodes the SMCCC function ID and returns PSCI_NOT_SUPPORTED for
//! function IDs we do not yet emulate. The real CPU_ON / CPU_OFF /
//! SYSTEM_RESET / AFFINITY_INFO bodies arrive in later waves once the
//! multi-vCPU state machine is wired up in `vcpu.zig`.

const zag = @import("zag");

const vcpu_mod = zag.arch.aarch64.kvm.vcpu;

const VCpu = vcpu_mod.VCpu;

/// SMCCC function IDs for PSCI. Values taken from DEN 0022F Table 5.1.
/// Zag uses the SMC64 entry points (bit 30 set) because guests are
/// AArch64; SMC32 aliases are forwarded to the VMM.
pub const FunctionId = enum(u32) {
    psci_version = 0x8400_0000,
    cpu_suspend = 0xC400_0001,
    cpu_off = 0x8400_0002,
    cpu_on = 0xC400_0003,
    affinity_info = 0xC400_0004,
    migrate = 0xC400_0005,
    migrate_info_type = 0x8400_0006,
    migrate_info_up_cpu = 0xC400_0007,
    system_off = 0x8400_0008,
    system_reset = 0x8400_0009,
    psci_features = 0x8400_000A,
    _,
};

/// PSCI return codes (DEN 0022F §5.2.2). `not_supported` is the value
/// an unimplemented function returns; guests treat it as a hint that a
/// feature is absent.
pub const ReturnCode = enum(i32) {
    success = 0,
    not_supported = -1,
    invalid_parameters = -2,
    denied = -3,
    already_on = -4,
    on_pending = -5,
    internal_failure = -6,
    not_present = -7,
    disabled = -8,
    invalid_address = -9,
};

/// PSCI version we advertise when we eventually implement `psci_version`:
/// PSCIv1.2 (major=1, minor=2 in the low 32 bits).
pub const VERSION_1_2: u32 = 0x0001_0002;

/// Dispatch result. `handled` means the call was resolved inline and x0
/// has been written with the result; the caller should advance PC and
/// resume the guest. `forward_to_vmm` means the call is outside the PSCI
/// range (or a function we chose to defer) and should surface to the
/// VMM as an SMCCC exit.
pub const Outcome = enum { handled, forward_to_vmm };

/// Dispatch an HVC/SMC call whose X0 holds an SMCCC function ID.
///
/// For M2 every real PSCI function returns PSCI_NOT_SUPPORTED. This
/// shape is deliberate: a guest that calls `CPU_ON` will see the call
/// fail gracefully and surface the failure through its own boot path,
/// which is strictly better than a silent hang.
///
/// TODO(m3): implement CPU_ON / CPU_OFF / SYSTEM_OFF / SYSTEM_RESET /
/// PSCI_VERSION / AFFINITY_INFO with real bodies that drive the vCPU
/// state machine in `vcpu.zig`.
pub fn dispatch(vcpu_obj: *VCpu) Outcome {
    const fid_raw: u32 = @truncate(vcpu_obj.guest_state.x0);
    const fid: FunctionId = @enumFromInt(fid_raw);

    const reply: u64 = switch (fid) {
        .psci_version,
        .cpu_suspend,
        .cpu_off,
        .cpu_on,
        .affinity_info,
        .migrate,
        .migrate_info_type,
        .migrate_info_up_cpu,
        .system_off,
        .system_reset,
        .psci_features,
        => @bitCast(@as(i64, @intFromEnum(ReturnCode.not_supported))),
        _ => return .forward_to_vmm,
    };

    vcpu_obj.guest_state.x0 = reply;
    return .handled;
}

/// The inclusive SMCCC function-ID range reserved for PSCI
/// (DEN 0022F §5.1). Used by the HVC classifier to decide whether an
/// HVC0 should attempt PSCI dispatch before falling back to a generic
/// SMCCC exit.
pub const SMCCC_PSCI_RANGE_LOW: u32 = 0x8400_0000;
pub const SMCCC_PSCI_RANGE_HIGH: u32 = 0x8400_001F;
pub const SMCCC_PSCI_RANGE64_LOW: u32 = 0xC400_0000;
pub const SMCCC_PSCI_RANGE64_HIGH: u32 = 0xC400_001F;

/// True if `fid` lies inside either the SMC32 or SMC64 PSCI function
/// ID window.
pub fn isPsciFid(fid: u32) bool {
    return (fid >= SMCCC_PSCI_RANGE_LOW and fid <= SMCCC_PSCI_RANGE_HIGH) or
        (fid >= SMCCC_PSCI_RANGE64_LOW and fid <= SMCCC_PSCI_RANGE64_HIGH);
}
