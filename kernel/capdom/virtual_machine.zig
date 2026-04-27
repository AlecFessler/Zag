//! Virtual Machine — guest execution environment with its own guest
//! physical address space. Execution contexts enter guest mode within
//! a VM to run. See spec §[virtual_machine].
//!
//! Capability-domain lifetime; the VM handle is non-transferable so
//! exactly one user-visible handle exists (held by the binding
//! capability domain). vCPU ECs back-reference the VM through their
//! `vm` field. UAF protection on those back-refs comes from
//! `_gen_lock`.

const std = @import("std");
const zag = @import("zag");

const arch_smp = zag.arch.dispatch.smp;
const capability = zag.caps.capability;
const cd_mod = zag.capdom.capability_domain;
const ec_mod = zag.sched.execution_context;
const errors = zag.syscall.errors;
const port_mod = zag.sched.port;
const vm_dispatch = zag.arch.dispatch.vm;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const PageFrameCaps = zag.memory.page_frame.PageFrameCaps;
const Port = zag.sched.port.Port;
const Priority = zag.sched.execution_context.Priority;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const VAddr = zag.memory.address.VAddr;
const VarPageSize = zag.capdom.var_range.PageSize;
const Word0 = zag.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for VM handles.
/// Spec §[virtual_machine] cap layout — exact cap bits TBD beyond
/// `policy` and `restart_policy`.
pub const VmCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    policy: bool = false,
    restart_policy: u1 = 0,
    _reserved: u12 = 0,
};

pub const VirtualMachine = struct {
    /// Slab generation lock. Validates `SlabRef(VirtualMachine)`
    /// liveness AND guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Owning capability domain. VM cannot outlive its owner.
    /// Set at create_virtual_machine; immutable.
    domain: *CapabilityDomain,

    /// Physical address of the guest's second-stage / nested page-
    /// table root (EPT root on Intel, NPT root on AMD, stage-2 root
    /// on aarch64). Mutated by `map_guest` / `unmap_guest`.
    guest_pt_root: PAddr,

    /// Arch-specific per-VM control state — VMCS / VMCB / stage-2
    /// translation regime, kernel-emulated LAPIC/IOAPIC/timer state,
    /// intercept/passthrough configuration, etc. Allocated out-of-
    /// band, layout per arch. Type-erased here; concrete type in
    /// `arch.dispatch.vm`.
    arch_state: ?*anyopaque = null,

    /// Page frame holding the seeded `VmPolicy`. Per spec the kernel
    /// retains a reference on this page frame for the VM's lifetime so
    /// the policy backing pages cannot be freed under guest exits that
    /// consult them.
    policy_pf: ?*PageFrame = null,

    /// VM policy bits (per spec field0 / cap word `policy`). Encoding
    /// TBD as VM creation cap bits get fleshed out — placeholder.
    policy: u8 = 0,
};

pub const Allocator = SecureSlab(VirtualMachine, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. VM handles are non-transferable;
/// delete tears down vCPUs, guest memory, and arch state.
pub fn releaseHandle(vm: *VirtualMachine) void {
    destroyVm(vm);
}

// ── External API ─────────────────────────────────────────────────────

/// `create_virtual_machine` syscall handler. Spec §[virtual_machine].
pub fn createVirtualMachine(caller: *ExecutionContext, caps: u64, policy_pf: u64) i64 {
    if (caps >> 16 != 0) return errors.E_INVAL;
    if (policy_pf >> 12 != 0) return errors.E_INVAL;

    const requested_caps: u16 = @truncate(caps);

    const domain = caller.domain.lock(@src()) catch return errors.E_BADCAP;
    defer caller.domain.unlock();

    // Spec: handle is non-transferable, exactly one per domain.
    if (domain.vm != null) return errors.E_FULL;

    const self_caps_struct: cd_mod.CapabilityDomainCaps = @bitCast(readSelfCaps(domain));
    if (!self_caps_struct.crvm) return errors.E_PERM;

    const vm_ceiling: u8 = @truncate(readSelfField0(domain) >> 48);
    if ((requested_caps & vm_ceiling) != requested_caps) return errors.E_PERM;

    const policy_pf_obj = lookupPageFrame(domain, @truncate(policy_pf)) orelse
        return errors.E_BADCAP;

    const new_vm = allocVm(domain, policy_pf_obj) catch {
        return errors.E_NOMEM;
    };

    const vm_gen = new_vm._gen_lock.currentGen();
    const erased = capability.ErasedSlabRef{
        .ptr = @ptrCast(new_vm),
        .gen = @intCast(vm_gen),
    };

    const slot = cd_mod.mintHandle(
        domain,
        erased,
        .virtual_machine,
        requested_caps,
        0,
        0,
    ) catch {
        destroyVm(new_vm);
        return errors.E_FULL;
    };

    domain.vm = new_vm;
    // Spec §[error_codes] / §[capabilities]: pack Word0 so the type
    // tag in bits 12..15 disambiguates a real handle word from the
    // small-positive error range 1..15.
    return @intCast(capability.Word0.pack(slot, .virtual_machine, requested_caps));
}

/// `create_vcpu` syscall handler. Spec §[virtual_machine].create_vcpu.
pub fn createVcpu(
    caller: *ExecutionContext,
    caps: u64,
    vm_handle: u64,
    affinity: u64,
    exit_port: u64,
) i64 {
    // caps[1]: bits 0-15 caps, bits 32-33 priority, others reserved.
    if (caps & ~@as(u64, 0x0000_0003_0000_FFFF) != 0) return errors.E_INVAL;
    if (vm_handle >> 12 != 0) return errors.E_INVAL;
    if (exit_port >> 12 != 0) return errors.E_INVAL;

    const requested_caps: u16 = @truncate(caps);
    const requested_priority: Priority = @enumFromInt(@as(u2, @truncate((caps >> 32) & 0x3)));

    const domain = caller.domain.lock(@src()) catch return errors.E_BADCAP;
    defer caller.domain.unlock();

    const self_caps_struct: cd_mod.CapabilityDomainCaps = @bitCast(readSelfCaps(domain));
    if (!self_caps_struct.crec) return errors.E_PERM;
    if (@intFromEnum(requested_priority) > self_caps_struct.pri) return errors.E_PERM;

    const ec_inner_ceiling: u8 = @truncate(readSelfField0(domain));
    if ((requested_caps & ec_inner_ceiling) != requested_caps) return errors.E_PERM;

    if (affinity != 0) {
        const cores = arch_smp.coreCount();
        const valid_mask: u64 = if (cores >= 64)
            std.math.maxInt(u64)
        else
            (@as(u64, 1) << @as(u6, @intCast(cores))) - 1;
        if (affinity & ~valid_mask != 0) return errors.E_INVAL;
    }

    const vm = lookupVirtualMachine(domain, @truncate(vm_handle)) orelse
        return errors.E_BADCAP;

    const port = lookupPort(domain, @truncate(exit_port)) orelse
        return errors.E_BADCAP;

    const vcpu_ec = allocVcpu(vm, domain, affinity, port) catch
        return errors.E_NOMEM;
    vcpu_ec.priority = requested_priority;

    const ec_gen = vcpu_ec._gen_lock.currentGen();
    const erased = capability.ErasedSlabRef{
        .ptr = @ptrCast(vcpu_ec),
        .gen = @intCast(ec_gen),
    };

    const slot = cd_mod.mintHandle(
        domain,
        erased,
        .execution_context,
        requested_caps,
        @intFromEnum(requested_priority),
        affinity,
    ) catch return errors.E_FULL;

    // Spec §[virtual_machine].create_vcpu test 12: an initial vm_exit
    // event is delivered immediately so the creator installs real
    // entry state through the standard recv/reply lifecycle.
    port_mod.fireVmExit(vcpu_ec, INITIAL_STATE_SUBCODE, .{ 0, 0, 0 });

    // Spec §[error_codes] / §[capabilities]: pack Word0 so the type
    // tag in bits 12..15 disambiguates a real handle word from the
    // small-positive error range 1..15.
    return @intCast(capability.Word0.pack(slot, .execution_context, requested_caps));
}

/// `map_guest` syscall handler. Spec §[virtual_machine].map_guest.
pub fn mapGuest(caller: *ExecutionContext, vm_handle: u64, pairs: []const u64) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;
    if (pairs.len == 0 or pairs.len % 2 != 0) return errors.E_INVAL;

    const domain = caller.domain.lock(@src()) catch return errors.E_BADCAP;
    defer caller.domain.unlock();

    const vm = lookupVirtualMachine(domain, @truncate(vm_handle)) orelse
        return errors.E_BADCAP;

    const pair_count = pairs.len / 2;

    // Pre-validate every pair before any stage-2 mutation. Partial
    // installs would leave un-named mappings (`unmap_guest` resolves
    // by page_frame handle, not guest_addr) so an unwound failure
    // could still alter the address space.
    var i: usize = 0;
    while (i < pair_count) {
        const guest_addr = pairs[2 * i];
        const pf_handle_word = pairs[2 * i + 1];
        if (pf_handle_word >> 12 != 0) return errors.E_INVAL;
        const pf = lookupPageFrame(domain, @truncate(pf_handle_word)) orelse
            return errors.E_BADCAP;
        const stride = pageStride(pf.sz);
        if (guest_addr % stride != 0) return errors.E_INVAL;

        var j: usize = 0;
        while (j < i) {
            const other_pf = lookupPageFrame(domain, @truncate(pairs[2 * j + 1])) orelse
                return errors.E_BADCAP;
            if (rangesOverlap(guest_addr, pf, pairs[2 * j], other_pf)) return errors.E_INVAL;
            j += 1;
        }
        i += 1;
    }

    i = 0;
    while (i < pair_count) {
        const pf_slot: u12 = @truncate(pairs[2 * i + 1]);
        const pf = lookupPageFrame(domain, pf_slot) orelse return errors.E_BADCAP;
        const pf_caps: PageFrameCaps = @bitCast(Word0.caps(domain.user_table[pf_slot].word0));
        const rc = installPageFrame(vm, pairs[2 * i], pf, pageFramePerms(pf_caps));
        if (rc != 0) return rc;
        i += 1;
    }

    return 0;
}

/// `unmap_guest` syscall handler. Spec §[virtual_machine].unmap_guest.
pub fn unmapGuest(caller: *ExecutionContext, vm_handle: u64, page_frames: []const u64) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;
    if (page_frames.len == 0) return errors.E_INVAL;

    const domain = caller.domain.lock(@src()) catch return errors.E_BADCAP;
    defer caller.domain.unlock();

    const vm = lookupVirtualMachine(domain, @truncate(vm_handle)) orelse
        return errors.E_BADCAP;

    for (page_frames) |pf_handle_word| {
        if (pf_handle_word >> 12 != 0) return errors.E_INVAL;
        const pf = lookupPageFrame(domain, @truncate(pf_handle_word)) orelse
            return errors.E_BADCAP;
        const rc = uninstallPageFrame(vm, pf);
        if (rc != 0) return rc;
    }

    return 0;
}

/// `vm_inject_irq` syscall handler. Spec §[virtual_machine].vm_inject_irq.
/// Thin wrapper around `dispatch.vm.vmInjectIrq` — the syscall trampoline
/// has already validated the VM handle and stripped the `assert` flag's
/// reserved bits.
pub fn vmInjectIrq(
    caller: *ExecutionContext,
    vm_handle: u64,
    irq_num: u64,
    assert: u64,
) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;

    const domain = caller.domain.lock(@src()) catch return errors.E_BADCAP;
    defer caller.domain.unlock();

    const slot: u12 = @truncate(vm_handle);
    const vm = lookupVirtualMachine(domain, slot) orelse return errors.E_BADCAP;

    const irq32: u32 = @truncate(irq_num);
    const assert_bit: bool = (assert & 0x1) != 0;
    vm_dispatch.vmInjectIrq(vm, irq32, assert_bit);
    return 0;
}

/// `vm_set_policy` syscall handler. Spec §[virtual_machine].vm_set_policy.
/// Proxies to `dispatch.vm.applyVmPolicyTable` for the per-arch encoding.
pub fn applyVmPolicyTable(
    caller: *ExecutionContext,
    vm_handle: u64,
    kind: u8,
    entries: []const u64,
) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;

    const domain = caller.domain.lock(@src()) catch return errors.E_BADCAP;
    defer caller.domain.unlock();

    const slot: u12 = @truncate(vm_handle);
    _ = lookupHandle(domain, slot, .virtual_machine) orelse return errors.E_BADCAP;

    const vm_caps: VmCaps = @bitCast(Word0.caps(domain.user_table[slot].word0));
    if (!vm_caps.policy) return errors.E_PERM;

    const vm = lookupVirtualMachine(domain, slot) orelse return errors.E_BADCAP;
    return vm_dispatch.applyVmPolicyTable(vm, kind, entries);
}

// ── Internal API ─────────────────────────────────────────────────────

/// Initial-state vm_exit sub-code delivered immediately on
/// `create_vcpu` so the creator can install real guest state via
/// reply. Per-arch dispatch maps this sentinel to the architecture's
/// initial-state slot before the first `enterGuest`.
pub const INITIAL_STATE_SUBCODE: u8 = 0xFF;

/// Allocate a VM bound to `domain`. Allocates stage-2 page-table root
/// from PMM, allocates arch control structure, retains a reference on
/// `policy_pf`. Spec §[virtual_machine].create_virtual_machine.
fn allocVm(domain: *CapabilityDomain, policy_pf: *PageFrame) !*VirtualMachine {
    const ref = try slab_instance.create();
    const new_vm = ref.ptr;
    const gen: u63 = @intCast(ref.gen);

    new_vm.domain = domain;
    new_vm.arch_state = null;
    new_vm.policy_pf = null;
    new_vm.policy = 0;

    new_vm.guest_pt_root = vm_dispatch.allocStage2Root(new_vm) catch |err| {
        slab_instance.destroy(new_vm, gen) catch {};
        return err;
    };

    new_vm.arch_state = vm_dispatch.allocVmArchState(new_vm, policy_pf) catch |err| {
        vm_dispatch.freeStage2Root(new_vm);
        slab_instance.destroy(new_vm, gen) catch {};
        return err;
    };

    incPageFrameRef(policy_pf);
    new_vm.policy_pf = policy_pf;

    return new_vm;
}

/// Final teardown — frees guest memory mappings, tears down emulated
/// devices, frees arch state and stage-2 root, drops the held
/// `policy_pf` reference, clears `domain.vm`, returns slab slot.
fn destroyVm(vm: *VirtualMachine) void {
    if (vm.policy_pf) |pf| {
        decPageFrameRef(pf);
        vm.policy_pf = null;
    }
    vm_dispatch.freeVmArchState(vm);
    vm_dispatch.freeStage2Root(vm);
    vm.domain.vm = null;
    const gen = vm._gen_lock.currentGen();
    slab_instance.destroy(vm, gen) catch {};
}

/// Install `pf` at `guest_addr` in stage-2 tables; increments mapcnt.
/// Per-page loop: each page in the page_frame is mapped contiguously
/// at `guest_addr + i * pf.sz`. `perms` carries the cap-derived stage-2
/// rwx envelope — guest accesses outside this envelope take a stage-2
/// fault per spec §[virtual_machine].map_guest test 07.
fn installPageFrame(vm: *VirtualMachine, guest_addr: u64, pf: *PageFrame, perms: MemoryPerms) i64 {
    const stride = pageStride(pf.sz);

    var i: u32 = 0;
    while (i < pf.page_count) {
        const ga = guest_addr + @as(u64, i) * stride;
        const ha = PAddr.fromInt(pf.phys_base.addr + @as(u64, i) * stride);
        vm_dispatch.stage2MapPage(vm, ga, ha, pf.sz, perms) catch {
            return errors.E_NOMEM;
        };
        i += 1;
    }

    incPageFrameMap(pf);
    return 0;
}

/// Remove `pf`'s installation from stage-2 tables; decrements mapcnt;
/// queues TLB shootdown to cores running this VM's vCPUs. Resolves
/// the host_phys to its installed guest_phys via dispatch.
fn uninstallPageFrame(vm: *VirtualMachine, pf: *PageFrame) i64 {
    // Stage-2 install metadata lives in dispatch (per-arch lookup
    // structure mirroring the EPT / stage-2 walk). The per-page
    // unmap+invalidate is dispatched in one shot since dispatch
    // already knows the guest_phys for `pf.phys_base`.
    const guest_phys = vm_dispatch.stage2UnmapPage(vm, pf.phys_base.addr, pf.sz) orelse
        return errors.E_NOENT;
    _ = guest_phys;

    var i: u32 = 1;
    while (i < pf.page_count) {
        const ha = pf.phys_base.addr + @as(u64, i) * pageStride(pf.sz);
        _ = vm_dispatch.stage2UnmapPage(vm, ha, pf.sz);
        i += 1;
    }

    vm_dispatch.invalidateStage2Range(vm, pf.phys_base.addr, pf.sz, pf.page_count);
    decPageFrameMap(pf);
    return 0;
}

/// Allocate a vCPU EC bound to this VM with `exit_port` set. The
/// vCPU EC is bound to the capability domain that holds the VM
/// handle (per spec); on a multi-domain handoff the holder is the
/// VM's owning domain.
fn allocVcpu(
    vm: *VirtualMachine,
    creator_domain: *CapabilityDomain,
    affinity: u64,
    exit_port: *Port,
) !*ExecutionContext {
    _ = creator_domain;

    const vcpu_ec = try ec_mod.allocExecutionContext(
        vm.domain,
        VAddr.fromInt(0),
        0,
        affinity,
        .normal,
        vm,
        exit_port,
    );

    try vm_dispatch.allocVcpuArchState(vm, vcpu_ec);

    return vcpu_ec;
}

/// Scheduler-dispatch entry point — load guest state from `vcpu_ec.ctx`
/// into VMCS/VMCB/sysregs, then world-switch into the guest. Returns
/// when the guest exits; the caller invokes `handleGuestExit` next to
/// snapshot exit state and deliver the event on the vCPU's exit_port.
pub fn enterGuest(vcpu_ec: *ExecutionContext) void {
    vm_dispatch.loadGuestState(vcpu_ec);
    vm_dispatch.enterGuest(vcpu_ec);
}

/// Arch-dispatch VM-exit handler — saves live guest registers into
/// `vcpu_ec.ctx`, reads the per-arch exit info, and fires a vm_exit
/// event on the vCPU's bound `exit_port`. Suspension and reply-cap
/// minting flow through the standard event-delivery path.
/// Spec §[vm_exit_state].
pub fn handleGuestExit(vcpu_ec: *ExecutionContext) void {
    vm_dispatch.saveGuestState(vcpu_ec);
    const info = vm_dispatch.lastVmExitInfo(vcpu_ec);
    port_mod.fireVmExit(vcpu_ec, info.subcode, info.payload);
}

// ── Helpers ──────────────────────────────────────────────────────────

fn readSelfCaps(domain: *CapabilityDomain) u16 {
    return Word0.caps(domain.user_table[0].word0);
}

fn readSelfField0(domain: *CapabilityDomain) u64 {
    return domain.user_table[0].field0;
}

fn lookupHandle(domain: *CapabilityDomain, slot: u12, expected: CapabilityType) ?*KernelHandle {
    if (@as(u16, slot) >= capability.MAX_HANDLES_PER_DOMAIN) return null;
    const entry = &domain.kernel_table[slot];
    if (entry.ref.ptr == null) return null;
    if (Word0.typeTag(domain.user_table[slot].word0) != expected) return null;
    return entry;
}

fn lookupVirtualMachine(domain: *CapabilityDomain, slot: u12) ?*VirtualMachine {
    const handle = lookupHandle(domain, slot, .virtual_machine) orelse return null;
    const ref = capability.typedRef(VirtualMachine, handle.*) orelse return null;
    return ref.ptr;
}

fn lookupPageFrame(domain: *CapabilityDomain, slot: u12) ?*PageFrame {
    const handle = lookupHandle(domain, slot, .page_frame) orelse return null;
    const ref = capability.typedRef(PageFrame, handle.*) orelse return null;
    return ref.ptr;
}

fn lookupPort(domain: *CapabilityDomain, slot: u12) ?*Port {
    const handle = lookupHandle(domain, slot, .port) orelse return null;
    const ref = capability.typedRef(Port, handle.*) orelse return null;
    return ref.ptr;
}

fn pageStride(sz: VarPageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0x1000,
    };
}

fn rangesOverlap(addr_a: u64, pf_a: *PageFrame, addr_b: u64, pf_b: *PageFrame) bool {
    const end_a = addr_a + pageStride(pf_a.sz) * pf_a.page_count;
    const end_b = addr_b + pageStride(pf_b.sz) * pf_b.page_count;
    return addr_a < end_b and addr_b < end_a;
}

/// Translate a holder's PageFrame `r/w/x` cap bits into stage-2
/// permissions. Spec §[virtual_machine].map_guest test 07: a guest
/// access whose required rwx is not a subset of these bits delivers a
/// vm_exit (`ept` on x86-64, `stage2_fault` on aarch64).
fn pageFramePerms(caps_bits: PageFrameCaps) MemoryPerms {
    return .{
        .read = caps_bits.r,
        .write = caps_bits.w,
        .exec = caps_bits.x,
    };
}

/// Holder-side refcount + mapcnt accessors. The PageFrame module's
/// own equivalents are file-private; the `_gen_lock` guard semantics
/// are mirrored here so cross-object install paths cannot race a
/// concurrent PageFrame teardown. Mirrors the canonical pattern in
/// `memory/page_frame.zig`: when both counters reach 0 the decrementer
/// owns teardown and `destroyPageFrame` is invoked while still holding
/// the lock so the gen-bump on slot release cannot race with a
/// concurrent acquire.
fn incPageFrameRef(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    defer pf._gen_lock.unlock();
    pf.refcount +|= 1;
}

fn decPageFrameRef(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    if (pf.refcount > 0) pf.refcount -= 1;
    if (pf.refcount == 0 and pf.mapcnt == 0) {
        destroyPageFrame(pf);
        return;
    }
    pf._gen_lock.unlock();
}

fn incPageFrameMap(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    defer pf._gen_lock.unlock();
    pf.mapcnt +|= 1;
}

fn decPageFrameMap(pf: *PageFrame) void {
    pf._gen_lock.lock(@src());
    if (pf.mapcnt > 0) pf.mapcnt -= 1;
    if (pf.refcount == 0 and pf.mapcnt == 0) {
        destroyPageFrame(pf);
        return;
    }
    pf._gen_lock.unlock();
}

/// Final teardown — caller has observed both `refcount` and `mapcnt`
/// at zero under `_gen_lock`. Returns the slab slot via `destroyLocked`
/// which performs the gen bump as part of releasing the lock.
fn destroyPageFrame(pf: *PageFrame) void {
    const expected_gen: u63 = @intCast(pf._gen_lock.currentGen());
    zag.memory.page_frame.slab_instance.destroyLocked(pf, expected_gen);
}
