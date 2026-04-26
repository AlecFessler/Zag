//! Aarch64 VCpu object — scaffolding.
//!
//! Mirrors `kernel/arch/x64/kvm/vcpu.zig`. The VCpu represents a virtual
//! CPU: a kernel execution context that runs the guest via
//! `vm_hyp.vmResume` in a loop, interleaving inline exit handling and
//! delivery to the VMM via the VmExitBox.
//!
//! x64 → aarch64 notable differences:
//!   - Entry point. On x64 the vcpu EC executes `vcpu_entry` which
//!     loads VMCS + calls `vmx.vmResume`. On aarch64 the entry point is
//!     the same shape but uses EL2 sysregs instead of VMCS loads.
//!
//!   - Interrupt delivery. On x64 the vcpu's `guest_state.pending_eventinj`
//!     holds a VMCB EVENTINJ token. On aarch64 the vGIC owns pending
//!     virtual interrupts; we just flip a flag in GuestState and
//!     `vgic.prepareEntry` programs list registers on the next entry.
//!
//!   - Sysreg trap inline handling. On x64, CR accesses / CPUID are
//!     handled inline by `tryHandleInlineExit`. The aarch64 analogue
//!     handles sysreg traps (MSR/MRS) and ID register reads by looking
//!     them up in `vm.policy` and calling a shared helper that walks
//!     the IdRegResponse / SysregPolicy tables.

const std = @import("std");
const zag = @import("zag");

const kvm = zag.arch.aarch64.kvm;
const vm_hw = zag.arch.aarch64.vm;
const vm_hyp = zag.arch.aarch64.hyp;
const vm_mod = kvm.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VgicVcpuState = kvm.vgic.VcpuState;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const Vm = kvm.vm.Vm;
const VmExitInfo = zag.arch.dispatch.vm.VmExitInfo;
const VtimerState = kvm.vtimer.VtimerState;

pub const VCpuAllocator = SecureSlab(VCpu, 256);
pub var slab_instance: VCpuAllocator = undefined;

/// State of a vCPU. Accessed from multiple ECs (the vCPU's own EC,
/// `kickRunningVcpus`, the exit handler, and reply-side resume); all
/// reads/writes must use atomic load/store via `loadState`/`storeState`
/// helpers.
pub const VCpuState = enum(u8) {
    idle,
    running,
    exited,
    waiting_reply,
};

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
    /// Back-reference to the vCPU's owning ExecutionContext. The EC is
    /// what scheduler code observes; the VCpu carries arch-specific
    /// world-switch state.
    ec: SlabRef(ExecutionContext),
    vm: SlabRef(Vm),
    guest_state: vm_hw.GuestState = .{},
    /// Atomic state. Use `loadState`/`storeState`. Direct writes are only
    /// allowed inside regions already holding `vm._gen_lock`.
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(VCpuState.idle)),
    last_exit_info: vm_hw.VmExitInfo = .{ .unknown = 0 },
    /// Guest FPSIMD state (V0..V31, FPCR, FPSR). Saved/restored by `vmResume`
    /// across each guest entry. ARM ARM B1.2.2.
    guest_fxsave: vm_hw.FxsaveArea align(16) = vm_hw.fxsaveInit(),
    /// Per-vCPU scratch the EL2 hyp stub uses for the world-switch
    /// marshalling block (WorldSwitchCtx + HostSave). Lives inline in
    /// the VCpu so its PA is reachable by `PAddr.fromVAddr` while the
    /// stub runs with EL2 MMU off. See `arch.aarch64.hyp.ArchScratch`.
    arch_scratch: vm_hyp.ArchScratch align(16) = .{},
    /// Per-vCPU vGIC state: redistributor SGI/PPI bookkeeping plus the
    /// list-register shadow consumed by `vgic.prepareEntry` /
    /// `vgic.saveExit`. Initialized after the VCpu allocation and
    /// before the vcpu EC is started.
    /// See `kernel/arch/aarch64/kvm/vgic.zig`.
    vgic_state: VgicVcpuState = .{},
    /// Per-vCPU virtual timer save area (CNTVOFF_EL2 / CNTV_CTL_EL0 /
    /// CNTV_CVAL_EL0 / CNTKCTL_EL1). Loaded into the hardware just
    /// before world-switch entry and snapshotted back out on exit.
    /// See `kernel/arch/aarch64/kvm/vtimer.zig`.
    vtimer_state: VtimerState = .{},

    pub inline fn loadState(self: *const VCpu) VCpuState {
        return @enumFromInt(self.state.load(.acquire));
    }

    pub inline fn storeState(self: *VCpu, new_state: VCpuState) void {
        self.state.store(@intFromEnum(new_state), .release);
    }
};

// ---------------------------------------------------------------------------
// Cross-module bridge
// ---------------------------------------------------------------------------

/// Route an interrupt injection addressed by GuestState pointer into the
/// in-kernel vGIC. The caller passes `&vcpu_obj.guest_state`; we recover
/// the containing VCpu via `@fieldParentPtr("guest_state", ...)` because
/// the real injection state lives on the per-vCPU vGIC shadow (list
/// registers + SGI/PPI pending bits), not directly on GuestState.
///
/// `aarch64/vm.zig` cannot `@import("zag").arch.aarch64.kvm.vgic`
/// directly without a circular module dependency (kvm imports vm), so
/// this bridge lives in the KVM object layer where both the VCpu type
/// and the vGIC module are in scope.
///
/// Reference: GICv3 §11.2 "List registers", `vgic.injectInterrupt`.
pub fn injectInterrupt(guest_state: *vm_hw.GuestState, interrupt: vm_hw.GuestInterrupt) void {
    // `@fieldParentPtr` yields a `*align(@alignOf(GuestState)) VCpu`;
    // `VCpu` has a stricter alignment than `GuestState` so the cast
    // back to the natural-alignment pointer is sound — every caller
    // passes `&vcpu.guest_state` from a `VCpu` allocated by the VCpu
    // slab allocator, which preserves `VCpu`'s 16-byte alignment.
    const vcpu: *VCpu = @alignCast(@fieldParentPtr("guest_state", guest_state));
    kvm.vgic.injectInterrupt(&vcpu.vgic_state, interrupt);
}

// ── Spec-v3 dispatch backings (STUB) ─────────────────────────────────
//
// TODO(step 6): wire vCPU lifetime + run-loop into the spec-v3 model.
// vCPU EC creation flows through `capdom.virtual_machine.createVcpu`
// and `sched.execution_context.allocExecutionContext`. The run loop is
// driven by the scheduler dispatching the vCPU EC; `dispatch.vm.enterGuest`
// calls into this file's `enterGuest`. VM-exit delivery fires a vm_exit
// event on the EC's bound `exit_port` per spec
// §[virtual_machine].create_vcpu test 12.

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    _ = vm;
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn loadGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn saveGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn lastVmExitInfo(vcpu_ec: *ExecutionContext) VmExitInfo {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

pub fn vmEmulatedTimerArm(vcpu_ec: *ExecutionContext, deadline_ns: u64) void {
    _ = vcpu_ec;
    _ = deadline_ns;
    @panic("step 6: rewrite for spec-v3");
}

pub fn vmEmulatedTimerCancel(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
    @panic("step 6: rewrite for spec-v3");
}

// vm_mod is referenced by exit_box → vcpu cycle in the future; suppress
// unused warning until that integration lands.
comptime {
    _ = vm_mod;
}
