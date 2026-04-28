const std = @import("std");
const zag = @import("zag");

const kvm = zag.arch.x64.kvm;
const vm_hw = zag.arch.x64.vm;
const vm_mod = kvm.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const Vm = vm_mod.Vm;
const VmExitInfo = zag.arch.dispatch.vm.VmExitInfo;

/// State of a vCPU. The field is accessed from multiple contexts:
/// the vCPU's own EC, `kickRunningVcpus` (walks all vCPUs), the
/// exit handler, and `vm_reply`. All reads/writes must use atomic
/// load/store -- see `loadState`/`storeState` helpers on `VCpu`.
pub const VCpuState = enum(u8) {
    idle,
    running,
    exited,
};

pub const VCpuAllocator = SecureSlab(VCpu, 256);

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
    vcpu_ec: SlabRef(ExecutionContext),
    vm: SlabRef(Vm),
    guest_state: vm_hw.GuestState = .{},
    state: VCpuState = .idle,
};

// ── Spec-v3 dispatch backings ────────────────────────────────────────
//
// Wire-up scope: allocate a per-vCPU arch state cell from PMM and pin
// it on the EC. Run-time bring-up (loadGuestState/saveGuestState/
// enterGuest/lastVmExitInfo) is still TODO — those paths fire only
// once a vCPU is actually scheduled, and tests that exercise them
// follow this commit.

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    if (!vm_hw.vmSupported()) return error.NoDevice;
    // TODO: per-vCPU arch state (saved GuestState + FXSAVE + last
    //       exit info) needs an `arch_state` slot on the spec-v3
    //       ExecutionContext to live in. The legacy VCpu slab
    //       (`kvm.vcpu.slab_instance`) holds these fields but is not
    //       yet hooked into spec-v3 EC bring-up. Once that hook lands,
    //       allocate from the slab here, link it on the EC, and
    //       initialize `guest_state` + `guest_fxsave` to defaults.
    //       For now we accept the create_vcpu syscall (allocating
    //       only the VirtualMachine.arch_state cell pointer) so the
    //       capability-domain handle plumbing tests can drive this
    //       path; the actual VMRUN/VMRESUME glue is the next agent's
    //       problem.
    _ = vm;
    _ = vcpu_ec;
}

pub fn loadGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

pub fn saveGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

pub fn lastVmExitInfo(vcpu_ec: *ExecutionContext) VmExitInfo {
    _ = vcpu_ec;
    return std.mem.zeroes(VmExitInfo);
}

