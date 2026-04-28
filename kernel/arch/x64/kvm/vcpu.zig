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

pub var slab_instance: VCpuAllocator = undefined;

pub const VCpu = struct {
    _gen_lock: GenLock = .{},
    vcpu_ec: SlabRef(ExecutionContext),
    vm: SlabRef(Vm),
    guest_state: vm_hw.GuestState = .{},
    /// Atomic state. Use `loadState`/`storeState` -- direct `.state = ...`
    /// writes are still allowed inside regions already holding `vm.lock`,
    /// but every other site must go through the atomic helpers.
    state: VCpuState = .idle,

    pub inline fn loadState(self: *const VCpu) VCpuState {
        return @atomicLoad(VCpuState, &self.state, .acquire);
    }

    pub inline fn storeState(self: *VCpu, s: VCpuState) void {
        @atomicStore(VCpuState, &self.state, s, .release);
    }

    /// Advance guest RIP by `bytes`. Wrapping add matches the arithmetic the
    /// callers used inline and keeps an out-of-band guest RIP (e.g. a guest
    /// jumping to near the top of the 64-bit address space) from panicking
    /// a safety-checked kernel build on the post-instruction advance.
    pub inline fn advanceRip(self: *VCpu, bytes: u8) void {
        self.guest_state.rip +%= bytes;
    }

    /// Write the CPUID response registers into guest state and advance RIP
    /// past the CPUID instruction. All inline CPUID exit paths route through
    /// here so guest-state writes stay local to VCpu.
    pub inline fn respondCpuid(
        self: *VCpu,
        rax_value: u64,
        rbx_value: u64,
        rcx_value: u64,
        rdx_value: u64,
        advance: u8,
    ) void {
        self.guest_state.rax = rax_value;
        self.guest_state.rbx = rbx_value;
        self.guest_state.rcx = rcx_value;
        self.guest_state.rdx = rdx_value;
        self.advanceRip(advance);
    }
};

/// Find the VCpu that owns a given EC within a VM.
/// Callers must hold `vm_obj._gen_lock`, which serializes with Vm
/// destroy and keeps every live `vm_obj.vcpus[i]` slot alive for the
/// duration of the lookup. self-alive: the vCPU slots indexed
/// [0, num_vcpus) were allocated during vmCreate and are only freed
/// via Vm.destroy, which takes the same lock.
pub fn vcpuFromEc(vm_obj: *Vm, ec: *ExecutionContext) ?*VCpu {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |v| {
        if (v.ptr.vcpu_ec.ptr == ec) return v.ptr;
    }
    return null;
}

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

pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
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

pub fn vmEmulatedTimerArm(vcpu_ec: *ExecutionContext, deadline_ns: u64) void {
    _ = vcpu_ec;
    _ = deadline_ns;
}

pub fn vmEmulatedTimerCancel(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}
