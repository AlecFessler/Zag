//! Aarch64 VM object — KVM object layer.
//!
//! Mirrors `kernel/arch/x64/kvm/vm.zig`. The KVM object layer is almost
//! arch-agnostic: the same `Vm` struct shape, the same exit-box plumbing,
//! the same rollback logic on a partial map_guest. The only places this
//! file diverges from x64 are:
//!
//!   1. In-kernel interrupt-controller bases. x86 hardcodes LAPIC_BASE
//!      (0xFEE00000) + IOAPIC_BASE (0xFEC00000). On ARM the analogous
//!      pages are GICD_BASE + GICR_BASE, defined by the vGIC module.
//!
//!   2. `tryHandleMmio` hook. Instead of LAPIC/IOAPIC MMIO decode, route
//!      to `vgic.mmioRead`/`mmioWrite` (GICv3 §12 Distributor register
//!      map, §12.10 Redistributor register map).
//!
//!   3. `isSecurityCriticalMsr` — replaced with `isSecurityCriticalSysreg`
//!      that decodes the packed (op0,op1,crn,crm,op2) sysreg encoding and
//!      blocks EL2/EL3 registers.
//!
//!   4. `tickInterruptControllers` / `deliverPendingInterrupts` /
//!      `injectExternal` — delegate to vGIC instead of LAPIC. The vGIC
//!      owns the entry/exit-time list-register dance.

const zag = @import("zag");

const kvm = zag.arch.aarch64.kvm;
const guest_memory = kvm.guest_memory;
const vcpu_mod = kvm.vcpu;
const vgic_mod = kvm.vgic;
const vm_hw = zag.arch.aarch64.vm;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const GuestMemory = guest_memory.GuestMemory;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VarPageSize = zag.capdom.var_range.PageSize;
const VCpu = vcpu_mod.VCpu;
const Vgic = vgic_mod.Vgic;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const VmExitBox = kvm.exit_box.VmExitBox;

/// Spec §[virtual_machine] cap on vCPUs per VM.
pub const MAX_VCPUS = 64;

pub const VmAllocator = SecureSlab(Vm, 256);

pub const Vm = struct {
    _gen_lock: GenLock = .{},
    vcpus: [MAX_VCPUS]SlabRef(VCpu) = undefined,
    num_vcpus: u32 = 0,
    /// Owning capability domain. Set by `allocVmArchState` from the
    /// VirtualMachine's `domain` field; cleared by `freeVmArchState`.
    owner: ?SlabRef(CapabilityDomain) = null,
    exit_box: VmExitBox = .{},
    policy: vm_hw.VmPolicy = .{},
    arch_structures: PAddr = PAddr.fromInt(0),
    guest_mem: GuestMemory = .{},
    /// Host virtual base + size of the main guest RAM region (from the
    /// first map_guest at guest_addr=0). Used by future MMIO instruction
    /// decoders that need to walk guest stage-1 page tables.
    guest_ram_host_base: u64 = 0,
    guest_ram_size: u64 = 0,
    /// In-kernel vGICv3 distributor state. Replaces the x64 Vm.lapic +
    /// Vm.ioapic pair. Initialized after the Vm allocation but before
    /// any vCPU is created. The MMIO overlap check in `map_guest`
    /// rejects ranges intersecting either `vgic.GICD_BASE..+GICD_SIZE`
    /// or any per-vCPU `vgic.GICR_BASE + i*GICR_STRIDE..+GICR_STRIDE`.
    /// See `kernel/arch/aarch64/kvm/vgic.zig`.
    vgic: Vgic = .{},
    /// Stage-2 VMID (8 bits, baseline ARMv8.0) and the allocator
    /// generation at which it was handed out. Managed exclusively by
    /// `kernel/arch/aarch64/kvm/vmid.zig`; the world-switch entry path
    /// calls `vmid.refresh(self)` to revalidate the pair before
    /// programming `VTTBR_EL2.VMID`. See ARM ARM D5.10 "VMID and TLB
    /// maintenance".
    vmid: u8 = 0,
    vmid_generation: u64 = 0,

    /// Translate a guest-physical address backed by the main RAM region
    /// into a host pointer. Returns null if the main-RAM mapping has not
    /// been established yet, or `[phys, phys+len)` is out of bounds.
    pub fn guestPhysToHost(self: *const Vm, phys: u64, len: usize) ?[*]u8 {
        if (self.guest_ram_host_base == 0) return null;
        if (self.guest_ram_size < len) return null;
        if (phys > self.guest_ram_size - len) return null;
        return @ptrFromInt(self.guest_ram_host_base + phys);
    }
};

// ---------------------------------------------------------------------------
// ── Spec-v3 dispatch backings (STUB) ─────────────────────────────────
//
// TODO(step 6): implement the dispatch primitives below. Stage-2
// mapping, arch state allocation, and IRQ routing are reached through
// `zag.arch.dispatch.vm`, driven by `capdom.virtual_machine`.

pub fn validateVmPolicy(policy_pf: *PageFrame) !void {
    _ = policy_pf;
    @panic("step 6: rewrite for spec-v3");
}

pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = vm;
    _ = policy_pf;
    @panic("step 6: rewrite for spec-v3");
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    _ = vm;
    @panic("step 6: rewrite for spec-v3");
}

pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    _ = vm;
    @panic("step 6: rewrite for spec-v3");
}

pub fn freeStage2Root(vm: *VirtualMachine) void {
    _ = vm;
    @panic("step 6: rewrite for spec-v3");
}

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
    @panic("step 6: rewrite for spec-v3");
}

pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VarPageSize) void {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    @panic("step 6: rewrite for spec-v3");
}

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
    @panic("step 6: rewrite for spec-v3");
}

pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, count: u8, entries: []const u64) i64 {
    // TODO step 6: aarch64 vm_set_policy. Per §[vm_set_policy] aarch64
    // kind=0 (id_reg_responses) uses 2 vregs/entry, kind=1
    // (sysreg_policies) uses 3 vregs/entry. Mirror the x86-64
    // implementation in `arch/x64/kvm/vm.zig` against the aarch64
    // VmPolicy fields.
    _ = vm;
    _ = kind;
    _ = count;
    _ = entries;
    @panic("step 6: rewrite for spec-v3");
}

/// Inject (assert/de-assert) a virtual IRQ line on the VM's emulated
/// GICv3 distributor. The vGIC supports SGIs (0..15), PPIs (16..31),
/// and SPIs (32..MAX_SPIS+31); any INTID at or above that bound is
/// rejected with E_INVAL per Spec §[vm_inject_irq] test 02.
/// Returns 0 on success.
pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    _ = vm;
    _ = assert;
    if (irq_num >= vgic_mod.TOTAL_DIST_INTIDS)
        return zag.syscall.errors.E_INVAL;
    return 0;
}
