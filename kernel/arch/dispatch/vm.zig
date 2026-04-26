const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const Range = zag.utils.range.Range;
const VarPageSize = zag.capdom.var_range.PageSize;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;

// Generic-kernel-facing VM dispatch. Arch-internal primitives (guest-page
// mapping, interrupt injection, world-switch, sysreg passthrough, etc.)
// are reached directly by the per-arch VMM code — they don't belong in
// dispatch because no generic-kernel callers need them. This module
// exposes only what the scheduler, process layer, and syscall layer use.

// --- Init ---------------------------------------------------------------

pub fn vmInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmInit(),
        .aarch64 => aarch64.vm.vmInit(),
        else => unreachable,
    }
}

pub fn vmPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmPerCoreInit(),
        .aarch64 => {
            aarch64.vm.vmPerCoreInit();
            // EL2 vector-table install is a per-core concern but lives in
            // the hyp.zig half of the aarch64 VM split; keep the call-out
            // here so vm.zig does not need a back-reference into hyp.
            aarch64.hyp.installHypVectors();
        },
        else => unreachable,
    }
}

/// BSP post-bootloader handoff. On aarch64, when UEFI's firmware drops
/// us at EL2 (only observable by the bootloader, which signals via
/// `boot_info.arrived_at_el2`), arm the hyp-stub gate and install the
/// kernel's EL2 vector table — must run before secondaries start since
/// only the BSP inherits the bootloader's EL2 vector stub. No-op on x86.
pub fn bspBootHandoff(arrived_at_el2: bool) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => if (arrived_at_el2) {
            aarch64.vm.hyp_stub_installed = true;
            aarch64.hyp.installHypVectors();
        },
        else => unreachable,
    }
}

pub fn initVmSlab(data_range: Range, ptrs_range: Range, links_range: Range) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vm.slab_instance = x64.kvm.vm.VmAllocator.init(data_range, ptrs_range, links_range),
        .aarch64 => aarch64.kvm.vm.slab_instance = aarch64.kvm.vm.VmAllocator.init(data_range, ptrs_range, links_range),
        else => {},
    }
}

pub fn initVcpuSlab(data_range: Range, ptrs_range: Range, links_range: Range) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.kvm.vcpu.slab_instance = x64.kvm.vcpu.VCpuAllocator.init(data_range, ptrs_range, links_range),
        .aarch64 => aarch64.kvm.vcpu.slab_instance = aarch64.kvm.vcpu.VCpuAllocator.init(data_range, ptrs_range, links_range),
        else => {},
    }
}

// ── Spec v3 VM dispatch primitives ───────────────────────────────────
// Fine-grained per-VM and per-vCPU control surface tied to the spec-v3
// VirtualMachine / ExecutionContext objects.

/// Allocate per-VM arch state (VMCS/VMCB region for the VM-level
/// fields, stage-2 control structures, kernel-emulated interrupt
/// controller state). `policy_pf` carries the create-time VM policy
/// page. Spec §[virtual_machine].create_virtual_machine.
pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = vm;
    _ = policy_pf;
    switch (builtin.cpu.arch) {
        .x86_64 => return error.NotImplemented,
        .aarch64 => return error.NotImplemented,
        else => unreachable,
    }
}

/// Free per-VM arch state allocated by `allocVmArchState`. Caller has
/// already torn down all vCPUs and stage-2 mappings.
pub fn freeVmArchState(vm: *VirtualMachine) void {
    _ = vm;
}

/// Allocate per-vCPU arch state (VMCS / VMCB save area, sysreg bank).
/// Stored on the vCPU EC. Spec §[virtual_machine].create_vcpu.
pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    _ = vm;
    _ = vcpu_ec;
    switch (builtin.cpu.arch) {
        .x86_64 => return error.NotImplemented,
        .aarch64 => return error.NotImplemented,
        else => unreachable,
    }
}

/// Free per-vCPU arch state.
pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

/// Allocate the stage-2 / nested page-table root for `vm` (EPT root on
/// Intel, NPT root on AMD, stage-2 TTBR on aarch64). Returned PAddr
/// is stored in `VirtualMachine.guest_pt_root`.
pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    _ = vm;
    switch (builtin.cpu.arch) {
        .x86_64 => return error.NotImplemented,
        .aarch64 => return error.NotImplemented,
        else => unreachable,
    }
}

/// Free the stage-2 root and any intermediate tables.
pub fn freeStage2Root(vm: *VirtualMachine) void {
    _ = vm;
}

/// Map a single guest page in the VM's stage-2 tables.
/// Spec §[virtual_machine].map_guest.
pub fn stage2MapPage(
    vm: *VirtualMachine,
    guest_phys: u64,
    host_phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    _ = vm;
    _ = guest_phys;
    _ = host_phys;
    _ = sz;
    _ = perms;
    switch (builtin.cpu.arch) {
        .x86_64 => return error.NotImplemented,
        .aarch64 => return error.NotImplemented,
        else => unreachable,
    }
}

/// Unmap a single guest page from stage-2. Returns the previously
/// bound host physical address if any.
/// Spec §[virtual_machine].unmap_guest.
pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VarPageSize) ?PAddr {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    switch (builtin.cpu.arch) {
        .x86_64 => return null,
        .aarch64 => return null,
        else => unreachable,
    }
}

/// Stage-2 TLB shootdown across cores currently running this VM's
/// vCPUs. Required after stage-2 unmaps or permission downgrades.
pub fn invalidateStage2Range(
    vm: *VirtualMachine,
    guest_phys: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    _ = page_count;
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {},
        else => unreachable,
    }
}

/// Load saved guest state from `vcpu_ec.ctx` into VMCS/VMCB or sysregs
/// in preparation for `enterGuest`.
pub fn loadGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

/// Save the live guest register state into `vcpu_ec.ctx`. Called from
/// the VM-exit dispatch path before suspending the vCPU on its
/// `exit_port`. Spec §[vm_exit_state].
pub fn saveGuestState(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

/// VMLAUNCH/VMRESUME on x86-64 / `eret` from EL2 on aarch64. Returns
/// when the guest exits. Caller is responsible for `loadGuestState`
/// before and `saveGuestState` after.
pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}

/// Snapshot of the most recent VM exit, populated by the per-arch exit
/// handler. Subcode and payload encode per-arch reason bits according
/// to Spec §[vm_exit_state].
pub const VmExitInfo = struct {
    subcode: u8,
    payload: [3]u64,
};

/// Read the last VM-exit info captured for `vcpu_ec`. The kernel exit
/// path stores this immediately after exit so the suspension event
/// payload reflects the correct reason. Spec §[vm_exit_state].
pub fn lastVmExitInfo(vcpu_ec: *ExecutionContext) VmExitInfo {
    _ = vcpu_ec;
    return .{ .subcode = 0, .payload = .{ 0, 0, 0 } };
}

/// Apply a typed slice of VM policy entries to the VM (MSR bitmap,
/// sysreg passthrough table, exception passthrough mask, etc. — see
/// Spec §[vm_policy] for the per-kind encoding). Returns 0 on success
/// or a negative error code.
pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, entries: []const u64) i64 {
    _ = vm;
    _ = kind;
    _ = entries;
    return -1;
}

/// Inject (or de-assert) a virtual interrupt into the VM's emulated
/// interrupt controller. Spec §[virtual_machine].vm_inject_irq.
pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) void {
    _ = vm;
    _ = irq_num;
    _ = assert;
}

/// Arm an emulated guest timer that fires `deadline_ns` (monotonic).
/// Used by the in-kernel virtual timer device that exposes guest
/// vtimer behaviour without round-tripping every program through
/// userspace. Spec §[virtual_machine].
pub fn vmEmulatedTimerArm(vcpu_ec: *ExecutionContext, deadline_ns: u64) void {
    _ = vcpu_ec;
    _ = deadline_ns;
}

/// Cancel an emulated guest timer previously armed by
/// `vmEmulatedTimerArm`.
pub fn vmEmulatedTimerCancel(vcpu_ec: *ExecutionContext) void {
    _ = vcpu_ec;
}
