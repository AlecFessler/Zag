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
const vm_mod = kvm.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VgicVcpuState = kvm.vgic.VcpuState;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const Vm = kvm.vm.Vm;
const VmExitInfo = zag.arch.dispatch.vm.VmExitInfo;

pub const VCpuAllocator = SecureSlab(VCpu, 256);

pub const VCpuState = enum(u8) {
    idle,
    running,
    exited,
};

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
    ec: SlabRef(ExecutionContext),
    vm: SlabRef(Vm),
    guest_state: vm_hw.GuestState = .{},
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(@intFromEnum(VCpuState.idle)),
    vgic_state: VgicVcpuState = .{},
};

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

// vm_mod is referenced by exit_box → vcpu cycle in the future; suppress
// unused warning until that integration lands.
comptime {
    _ = vm_mod;
}
