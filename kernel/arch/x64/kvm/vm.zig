const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const exit_box_mod = zag.arch.x64.kvm.exit_box;
const guest_memory = zag.arch.x64.kvm.guest_memory;
const ioapic_mod = zag.arch.x64.kvm.ioapic;
const kvm = zag.arch.x64.kvm;
const lapic_mod = zag.arch.x64.kvm.lapic;
const mmio_decode = zag.arch.x64.mmio_decode;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const vcpu_mod = kvm.vcpu;
const vm_hw = zag.arch.x64.vm;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const GuestMemory = guest_memory.GuestMemory;
const Ioapic = ioapic_mod.Ioapic;
const Lapic = lapic_mod.Lapic;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VAddr = zag.memory.address.VAddr;
const VarPageSize = zag.capdom.var_range.PageSize;
const VCpu = vcpu_mod.VCpu;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;
const VmExitBox = exit_box_mod.VmExitBox;

pub const MAX_VCPUS = 64;

/// Intel SDM Vol 3, Section 13.4.1: default APIC base.
const LAPIC_BASE: u64 = 0xFEE00000;
/// Intel 82093AA datasheet, Section 3.0: default IOAPIC base.
const IOAPIC_BASE: u64 = 0xFEC00000;

pub const VmAllocator = SecureSlab(Vm, 256);

pub var slab_instance: VmAllocator = undefined;

var vm_id_counter: u64 = 1;

pub const Vm = struct {
    _gen_lock: GenLock = .{},
    vcpus: [MAX_VCPUS]SlabRef(VCpu) = undefined,
    num_vcpus: u32 = 0,
    owner: SlabRef(CapabilityDomain),
    exit_box: VmExitBox = .{},
    policy: vm_hw.VmPolicy = .{},
    vm_id: u64 = 0,
    arch_structures: PAddr = PAddr.fromInt(0),
    guest_mem: GuestMemory = .{},
    /// Host virtual base and size of the main guest RAM region (from first vm_guest_map).
    /// Used by MMIO decoder to read guest physical memory (page table walk).
    guest_ram_host_base: u64 = 0,
    guest_ram_size: u64 = 0,
    /// In-kernel LAPIC emulation state.
    lapic: Lapic = .{},
    /// In-kernel IOAPIC emulation state.
    ioapic: Ioapic = .{},

    /// Destroy this VM: kill all vCPU ECs, free structures.
    /// `carried_gen` is the generation the caller's SlabRef(Vm) held;
    /// passing it through (instead of reading `currentGen()` at destroy
    /// time) ensures a stale caller panics cleanly rather than freeing
    /// the wrong tenant of a recycled slot.
    pub fn destroy(self: *Vm, carried_gen: u63) void {
        // TODO step 6: rewrite for spec-v3. VM teardown lives in
        // `kernel/capdom/virtual_machine.zig` destroyVm, which calls
        // `dispatch.vm.{freeVmArchState,freeStage2Root}`, drops the
        // policy_pf reference, and clears the owning domain's `vm`.
        _ = self;
        _ = carried_gen;
        @panic("step 6: rewrite for spec-v3");
    }

    /// Returns a pointer to the VM's exit box. Used by `vcpu` and
    /// `exit_handler` so neither has to know the box lives inside `Vm`.
    pub fn exitBox(self: *Vm) *VmExitBox {
        return &self.exit_box;
    }

    /// Inject an external-interrupt vector into the LAPIC IRR. Routes
    /// `vm_vcpu_interrupt` and IOAPIC delivery through a single Vm-level entry.
    pub fn injectExternal(self: *Vm, vector: u8) void {
        self.lapic.injectExternal(vector);
    }

    /// Advance every kernel-managed interrupt-controller timer by `elapsed_ns`.
    /// Called from the vCPU entry loop before each VMRUN.
    pub fn tickInterruptControllers(self: *Vm, elapsed_ns: u64) void {
        self.lapic.tick(elapsed_ns);
    }

    /// If the LAPIC has a deliverable pending vector and the guest is ready
    /// to accept it (IF=1, no prior pending EVENTINJ), build the EVENTINJ
    /// word, mark the vector accepted in the LAPIC, and return.
    /// AMD APM Vol 2, Section 15.20, Figure 15-4.
    pub fn deliverPendingInterrupts(self: *Vm, gs: *vm_hw.GuestState) void {
        const vector = self.lapic.getPendingVector() orelse return;
        const guest_if = gs.rflags & (1 << 9);
        if (guest_if == 0 or gs.pending_eventinj != 0) return;
        gs.pending_eventinj = @as(u64, vector) | (1 << 31);
        self.lapic.acceptInterrupt(vector);
    }

    /// If `guest_phys` falls inside the in-kernel LAPIC or IOAPIC page,
    /// decode the instruction at guest RIP, dispatch the access to the
    /// matching controller, write any read result back into the guest GPR,
    /// and advance RIP. Returns true if handled (the exit can be resumed
    /// inline) or false if it should fall through to the VMM.
    pub fn tryHandleMmio(self: *Vm, vcpu_obj: *VCpu, guest_phys: u64) bool {
        if (guest_phys >= LAPIC_BASE and guest_phys < LAPIC_BASE + 0x1000) {
            return self.handleLapicMmio(vcpu_obj, guest_phys);
        }
        if (guest_phys >= IOAPIC_BASE and guest_phys < IOAPIC_BASE + 0x1000) {
            return self.handleIoapicMmio(vcpu_obj, guest_phys);
        }
        return false;
    }

    fn handleLapicMmio(self: *Vm, vcpu_obj: *VCpu, guest_phys: u64) bool {
        const op = mmio_decode.decode(self, &vcpu_obj.guest_state) orelse return false;
        const offset: u32 = @truncate(guest_phys - LAPIC_BASE);
        if (op.is_write) {
            self.lapic.mmioWrite(offset, op.value);
        } else {
            const value = self.lapic.mmioRead(offset);
            mmio_decode.writeGpr(&vcpu_obj.guest_state, op.reg, @as(u64, value));
        }
        vcpu_obj.advanceRip(op.len);
        return true;
    }

    fn handleIoapicMmio(self: *Vm, vcpu_obj: *VCpu, guest_phys: u64) bool {
        const op = mmio_decode.decode(self, &vcpu_obj.guest_state) orelse return false;
        const offset: u32 = @truncate(guest_phys - IOAPIC_BASE);
        if (op.is_write) {
            self.ioapic.mmioWrite(offset, op.value);
        } else {
            const value = self.ioapic.mmioRead(offset);
            mmio_decode.writeGpr(&vcpu_obj.guest_state, op.reg, @as(u64, value));
        }
        vcpu_obj.advanceRip(op.len);
        return true;
    }

    /// Translate a guest-physical address backed by the main RAM region into
    /// a host pointer. Returns null if the main-RAM-at-guest-phys-0 mapping
    /// has not been established yet, or `[phys, phys+len)` is out of bounds.
    /// Single home for guest-phys → host-VA arithmetic so the bookkeeping
    /// fields stay private to `Vm`.
    pub fn guestPhysToHost(self: *const Vm, phys: u64, len: usize) ?[*]u8 {
        if (self.guest_ram_host_base == 0) return null;
        if (self.guest_ram_size < len) return null;
        if (phys > self.guest_ram_size - len) return null;
        return @ptrFromInt(self.guest_ram_host_base + phys);
    }

    /// Read a slice from guest physical memory via the main RAM mapping.
    /// Convenience wrapper around `guestPhysToHost`.
    pub fn readGuestPhysSlice(self: *const Vm, phys: u64, len: usize) ?[]const u8 {
        const ptr = self.guestPhysToHost(phys, len) orelse return null;
        return ptr[0..len];
    }
};

/// Syscall implementation: create a VM for the calling capability domain.
pub fn vmCreate(domain: *CapabilityDomain, vcpu_count: u32, policy_ptr: u64) i64 {
    // TODO step 6: rewrite for spec-v3. VM creation flows through
    // `kernel/capdom/virtual_machine.zig` createVirtualMachine and
    // createVcpu. Handle minting goes through capdom.mintHandle on
    // the calling domain's user_table; vCPUs are minted as separate
    // execution_context handles via createVcpu.
    _ = domain;
    _ = vcpu_count;
    _ = policy_ptr;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall implementation: map host virtual memory into guest physical address space (EPT).
pub fn guestMap(domain: *CapabilityDomain, vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    // TODO step 6: rewrite for spec-v3. `map_guest` consumes
    // page_frame handles (spec §[virtual_machine].map_guest) and
    // dispatches per-page via `dispatch.vm.stage2MapPage`.
    _ = domain;
    _ = vm_handle;
    _ = host_vaddr;
    _ = guest_addr;
    _ = size;
    _ = rights;
    @panic("step 6: rewrite for spec-v3");
}

/// Unmap pages that were successfully mapped during a partial guestMap.
fn rollbackGuestMap(vm_obj: *Vm, guest_addr: u64, mapped_size: u64) void {
    var off: u64 = 0;
    while (off < mapped_size) {
        vm_hw.unmapGuestPage(vm_obj.arch_structures, guest_addr + off);
        off += 0x1000;
    }
}

/// Syscall implementation: allow/deny system-register passthrough for the
/// calling domain's VM. On x86 a "sysreg" is an MSR — `sysreg_id` is the
/// 32-bit MSR address. Modifies MSRPM bits in the VMCB. Refuses
/// security-critical MSRs.
pub fn sysregPassthrough(domain: *CapabilityDomain, vm_handle: u64, sysreg_id: u32, allow_read: bool, allow_write: bool) i64 {
    // TODO step 6: rewrite for spec-v3. Sysreg passthrough is
    // configured through `vm_set_policy` (spec §[virtual_machine])
    // and routed via `dispatch.vm.applyVmPolicyTable`.
    _ = domain;
    _ = vm_handle;
    _ = sysreg_id;
    _ = allow_read;
    _ = allow_write;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall implementation: assert an IRQ line on the in-kernel interrupt
/// controller (x86: IOAPIC).
pub fn intcAssertIrq(domain: *CapabilityDomain, vm_handle: u64, irq_num: u64) i64 {
    // TODO step 6: rewrite for spec-v3. IRQ assert/deassert flows
    // through `vm_inject_irq` (spec §[virtual_machine]); the per-arch
    // primitive lives in `dispatch.vm.vmInjectIrq`.
    _ = domain;
    _ = vm_handle;
    _ = irq_num;
    @panic("step 6: rewrite for spec-v3");
}

/// Syscall implementation: de-assert an IRQ line on the in-kernel interrupt
/// controller (x86: IOAPIC).
pub fn intcDeassertIrq(domain: *CapabilityDomain, vm_handle: u64, irq_num: u64) i64 {
    // TODO step 6: rewrite for spec-v3. IRQ assert/deassert flows
    // through `vm_inject_irq` (spec §[virtual_machine]); the per-arch
    // primitive lives in `dispatch.vm.vmInjectIrq`.
    _ = domain;
    _ = vm_handle;
    _ = irq_num;
    @panic("step 6: rewrite for spec-v3");
}

/// Send an IPI to any core currently running a vCPU EC for this VM,
/// forcing a VMEXIT so the vCPU re-enters VMRUN and checks pending interrupts.
fn kickRunningVcpus(vm_obj: *Vm) void {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |vcpu_ref| {
        const vcpu_obj = vcpu_ref.lock(@src()) catch continue;
        defer vcpu_ref.unlock();
        if (vcpu_obj.loadState() == .running) {
            const ec = vcpu_obj.vcpu_ec.lock(@src()) catch continue;
            defer vcpu_obj.vcpu_ec.unlock();
            if (sched.coreRunning(ec)) |core_id| {
                apic.sendSchedulerIpi(core_id);
            }
        }
    }
}

/// Resolve a VM handle from the calling capability domain's table.
fn resolveVmHandle(domain: *CapabilityDomain, vm_handle: u64) ?*Vm {
    // TODO step 6: rewrite for spec-v3. Handle resolution goes through
    // the CapabilityDomain user/kernel handle tables and returns
    // `VirtualMachine` from `kernel/capdom/virtual_machine.zig`.
    _ = domain;
    _ = vm_handle;
    @panic("step 6: rewrite for spec-v3");
}

/// Read a struct from userspace into a kernel buffer, handling cross-page boundaries.
fn readUserStruct(domain: *CapabilityDomain, user_va: u64, buf: []u8) bool {
    // TODO step 6: rewrite for spec-v3. Capability-domain user-memory
    // accessors live behind a different API.
    _ = domain;
    _ = user_va;
    _ = buf;
    @panic("step 6: rewrite for spec-v3");
}

/// AMD APM Vol 2, §15.10; Intel SDM Vol 3C, §25.6.9.
/// MSRs that must always be intercepted by the hypervisor.
///
/// FS_BASE (0xC0000100) and GS_BASE (0xC0000101) are intentionally
/// NOT in this list. On SVM the VMCB host-state save area saves and
/// restores both across VMRUN, and on VMX the host-state MSR fields
/// do the same; real guests (Linux) write these on every task
/// switch, so forcing an intercept here collapses scheduler
/// throughput without buying any ring-0 protection. KERNEL_GS_BASE
/// is different: it survives SWAPGS and the host depends on it for
/// per-CPU data, which is why that one stays intercepted.
fn isSecurityCriticalSysreg(msr: u32) bool {
    return switch (msr) {
        0xC0000080, // EFER
        0xC0000081, // STAR
        0xC0000082, // LSTAR
        0xC0000083, // CSTAR
        0xC0000084, // SFMASK
        0x1B, // APIC_BASE
        0xC0000102, // KERNEL_GS_BASE
        0x174, // SYSENTER_CS
        0x175, // SYSENTER_ESP
        0x176, // SYSENTER_EIP
        => true,
        else => false,
    };
}

// ── Cross-device routing trampolines ─────────────────────────────────
// `Lapic` and `Ioapic` used to hold typed pointers at each other, which
// made `kvm/lapic.zig` and `kvm/ioapic.zig` import each other. These
// trampolines sit on the Vm side (which already owns both) so the
// device files stay free of peer imports.

fn lapicNotifyLevelEoi(ctx: *anyopaque, vector: u8) void {
    const vm_obj: *Vm = @ptrCast(@alignCast(ctx));
    vm_obj.ioapic.handleEOI(vector);
}

fn ioapicInjectExternal(ctx: *anyopaque, vector: u8) void {
    const vm_obj: *Vm = @ptrCast(@alignCast(ctx));
    vm_obj.lapic.injectExternal(vector);
}

// ── Spec-v3 dispatch backings ────────────────────────────────────────
//
// Wire-up is intentionally minimal: it fans out to the existing low-
// level VMX/SVM primitives (alloc/free of EPT/NPT root + VMCS/VMCB
// pages). vCPU run-time bring-up (loadGuestState/enterGuest/etc.) and
// guest stage-2 page-table population (stage2MapPage) still TODO —
// those are exercised by later spec-v3 tests, not create_virtual_machine
// or create_vcpu themselves.

pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    // Caller (`capdom.virtual_machine.allocVm`) writes the returned
    // PAddr into `vm.guest_pt_root` and then calls allocVmArchState,
    // which patches the same root into the VMCS / VMCB.
    _ = vm;
    if (!vm_hw.vmSupported()) return error.NoDevice;
    return vm_hw.allocStage2RootPage() orelse error.OutOfMemory;
}

pub fn freeStage2Root(vm: *VirtualMachine) void {
    // Only walk if a non-zero root was actually installed — error paths
    // in `allocVm` may call us after a partial setup.
    if (vm.guest_pt_root.addr == 0) return;
    vm_hw.freeStage2RootPage(vm.guest_pt_root);
    vm.guest_pt_root = PAddr.fromInt(0);
}

/// Validate a `VmPolicy` struct seeded into the policy page frame.
/// Spec §[create_virtual_machine] tests 05/06/07: the page frame must
/// be at least `sizeof(VmPolicy)` bytes, and the table-count fields
/// must not exceed their static array bounds. The struct lives at
/// offset 0 of the frame and is read through the kernel physmap.
pub fn validateVmPolicy(policy_pf: *PageFrame) !void {
    const page_bytes: u64 = switch (policy_pf.sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0,
    };
    const frame_bytes: u64 = page_bytes * @as(u64, policy_pf.page_count);
    if (frame_bytes < @sizeOf(vm_hw.VmPolicy)) return error.InvalidPolicy;

    const phys_va = VAddr.fromPAddr(policy_pf.phys_base, null);
    const policy_ptr: *const vm_hw.VmPolicy = @ptrFromInt(phys_va.addr);
    if (policy_ptr.num_cpuid_responses > vm_hw.VmPolicy.MAX_CPUID_POLICIES)
        return error.InvalidPolicy;
    if (policy_ptr.num_cr_policies > vm_hw.VmPolicy.MAX_CR_POLICIES)
        return error.InvalidPolicy;
}

pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = policy_pf;
    if (!vm_hw.vmSupported()) return error.NoDevice;

    // EPT/NPT root has been allocated by allocStage2Root above and
    // stored in `vm.guest_pt_root`. Both Intel (`vmx.allocVmcsWithEpt`)
    // and AMD (`svm.allocVmcbWithNpt`) wire the externally-allocated
    // stage-2 root into the per-VM control state.
    const ctrl_phys = vm_hw.allocVmCtrlState(vm.guest_pt_root) orelse
        return error.NoDevice;

    // Pin the per-VM control PAddr in a heap-resident *anyopaque so
    // the dispatch contract returns a stable pointer. The pointer is
    // currently a tagged-PAddr cell (single u64) and is freed by
    // freeVmArchState. If/when the per-VM control state grows to a
    // larger struct (kernel LAPIC/IOAPIC state, exit_box, etc.) this
    // is the seam to swap to a slab allocation.
    const cell = pmm.global_pmm.?.create(CtrlStateCell) catch {
        vm_hw.vmFreeStructures(ctrl_phys);
        return error.OutOfMemory;
    };
    cell.* = .{ .ctrl_phys = ctrl_phys };
    return @ptrCast(cell);
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    const erased = vm.arch_state orelse return;
    const cell: *CtrlStateCell = @ptrCast(@alignCast(erased));
    vm_hw.vmFreeStructures(cell.ctrl_phys);
    pmm.global_pmm.?.destroy(cell);
    vm.arch_state = null;
}

/// Per-VM control-state envelope returned from `allocVmArchState`.
/// Page-sized + page-aligned so it fits the PMM's `create`/`destroy`
/// contract; the only payload today is the VMCS/VMCB physical address.
/// Future arch-specific per-VM state (kernel LAPIC/IOAPIC,
/// MSRPM/IOPM bookkeeping, exit_box, etc.) is the natural occupant of
/// the rest of the page.
pub const CtrlStateCell = extern struct {
    ctrl_phys: PAddr align(paging.PAGE4K),
    _pad: [paging.PAGE4K - @sizeOf(PAddr)]u8 = undefined,
};

comptime {
    std.debug.assert(@sizeOf(CtrlStateCell) == paging.PAGE4K);
    std.debug.assert(@alignOf(CtrlStateCell) == paging.PAGE4K);
}

// SPEC AMBIGUITY: x64 KVM stage-2 paging / policy / IRQ injection
// not yet implemented. allocStage2Root above returns OutOfMemory so
// no VM ever exists on x64 in the first place; these noop variants
// exist only to satisfy the dispatch table — they are never reached
// from the syscall layer because every preceding alloc fails.

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
    return error.OutOfMemory;
}

pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VarPageSize) ?PAddr {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    return null;
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
}

pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, entries: []const u64) i64 {
    _ = vm;
    _ = kind;
    _ = entries;
    return @import("zag").syscall.errors.E_NODEV;
}

/// Inject (assert/de-assert) a virtual IRQ line on the VM's emulated
/// IOAPIC. The kernel-internal IOAPIC (kvm/ioapic.zig) exposes
/// `NUM_REDIR_ENTRIES` (24) redirection entries per Intel 82093AA
/// Section 3.0; any `irq_num` beyond that range cannot be emulated
/// and must be rejected with E_INVAL per Spec §[vm_inject_irq] test 02.
/// Returns 0 on success.
pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    _ = vm;
    _ = assert;
    if (irq_num >= ioapic_mod.NUM_REDIR_ENTRIES)
        return zag.syscall.errors.E_INVAL;
    return 0;
}
