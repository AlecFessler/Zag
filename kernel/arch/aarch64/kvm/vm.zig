//! Aarch64 VM object — KVM object layer.
//!
//! Mirrors `kernel/arch/x64/kvm/vm.zig`. The KVM object layer is almost
//! arch-agnostic: the same `Vm` struct shape, the same perm-table
//! bookkeeping, the same exit-box plumbing, the same rollback logic on a
//! partial `guest_map`. The only places this file diverges from x64 are:
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

const std = @import("std");
const zag = @import("zag");

const aarch64_paging = zag.arch.aarch64.paging;
const gic = zag.arch.aarch64.gic;
const kvm = zag.arch.aarch64.kvm;
const guest_memory = kvm.guest_memory;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const stage2 = zag.arch.aarch64.stage2;
const vcpu_mod = kvm.vcpu;
const vgic_mod = kvm.vgic;
const vm_hw = zag.arch.aarch64.vm;
const vmid_mod = kvm.vmid;

const GenLock = zag.memory.allocators.secure_slab.GenLock;
const GuestMemory = guest_memory.GuestMemory;
const KernelObject = zag.perms.permissions.KernelObject;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.proc.process.Process;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const slabRefNow = zag.proc.process.slabRefNow;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const VAddr = zag.memory.address.VAddr;
const VCpu = vcpu_mod.VCpu;
const Vgic = vgic_mod.Vgic;
const VmExitBox = kvm.exit_box.VmExitBox;

/// Spec §4.2.16 cap on vCPUs per VM.
pub const MAX_VCPUS = 64;

pub const VmAllocator = SecureSlab(Vm, 256);
pub var slab_instance: VmAllocator = undefined;

var vm_id_counter: u64 = 1;

pub const Vm = struct {
    _gen_lock: GenLock = .{},
    vcpus: [MAX_VCPUS]SlabRef(VCpu) = undefined,
    num_vcpus: u32 = 0,
    owner: SlabRef(Process),
    exit_box: VmExitBox = .{},
    policy: vm_hw.VmPolicy = .{},
    vm_id: u64 = 0,
    arch_structures: PAddr = PAddr.fromInt(0),
    guest_mem: GuestMemory = .{},
    /// Host virtual base + size of the main guest RAM region (from the
    /// first vm_guest_map at guest_addr=0). Used by future MMIO instruction
    /// decoders that need to walk guest stage-1 page tables.
    guest_ram_host_base: u64 = 0,
    guest_ram_size: u64 = 0,
    /// In-kernel vGICv3 distributor state. Replaces the x64 Vm.lapic +
    /// Vm.ioapic pair. Initialized by `vmCreate` via `vgic.init` after
    /// the Vm allocation but before any vCPU is created. The MMIO
    /// overlap check in `guestMap` rejects ranges intersecting either
    /// `vgic.GICD_BASE..+GICD_SIZE` or any per-vCPU
    /// `vgic.GICR_BASE + i*GICR_STRIDE..+GICR_STRIDE`.
    /// See `kernel/arch/aarch64/kvm/vgic.zig`.
    vgic: Vgic = .{},
    /// Stage-2 VMID (8 bits, baseline ARMv8.0) and the allocator generation
    /// at which it was handed out. Managed exclusively by
    /// `kernel/arch/aarch64/kvm/vmid.zig`; the world-switch entry path calls
    /// `vmid.refresh(self)` to revalidate the pair before programming
    /// `VTTBR_EL2.VMID`. See ARM ARM D5.10 "VMID and TLB maintenance".
    vmid: u8 = 0,
    vmid_generation: u64 = 0,

    /// Destroy this VM: kill all vCPU threads, free guest memory and
    /// arch structures, clear the owner's vm pointer.
    /// `carried_gen` is the generation the caller's SlabRef(Vm) held;
    /// passing it through (instead of reading `currentGen()` at destroy
    /// time) ensures a stale caller panics cleanly rather than freeing
    /// the wrong tenant of a recycled slot.
    pub fn destroy(self: *Vm, carried_gen: u63) void {
        // self-alive: the vCPU slots were allocated by this VM at
        // create time and have not been freed until this loop runs;
        // no concurrent observer still holds a live ref to them
        // because the process's perm-table handles are cleared by the
        // caller (vmCreate rollback / process teardown) before
        // Vm.destroy runs.
        var i: u32 = 0;
        while (i < self.num_vcpus) {
            vcpu_mod.destroy(self.vcpus[i].ptr, @intCast(self.vcpus[i].gen));
            i += 1;
        }
        self.num_vcpus = 0;

        self.guest_mem.deinit(self.arch_structures);

        if (self.arch_structures.addr != 0) {
            stage2.vmFreeStructures(self.arch_structures);
        }

        // Drop the VMID. The allocator does not return the id to a free
        // list (see vmid.zig) — a rollover is the reclamation mechanism —
        // but we still clear the fields so any stray use after destroy
        // goes through the slow path and takes a fresh id.
        vmid_mod.release(self);

        // Clear owner's vm pointer. The owning Process is the caller of
        // the syscall that ended up here (vmCreate rollback or teardown
        // from process exit), so the slot is live — take the gen-lock
        // rather than reaching through `.ptr`.
        if (self.owner.lock()) |proc| {
            proc.vm = null;
            self.owner.unlock();
        } else |_| {}

        slab_instance.destroy(self, carried_gen) catch unreachable;
    }

    /// Returns a pointer to the VM's exit box.
    pub fn exitBox(self: *Vm) *VmExitBox {
        return &self.exit_box;
    }

    /// Inject a virtual interrupt into the in-kernel vGIC. Routes
    /// `vm_vcpu_interrupt` and SPI assertion through a single Vm-level
    /// entry. This is the rough analogue of x64 `injectExternal`, but on
    /// ARM "external" maps to "SPI" and is per-VM, not per-vCPU.
    pub fn assertSpi(self: *Vm, intid: u32) void {
        vgic_mod.assertSpi(&self.vgic, intid);
    }

    /// `tryHandleMmio` — called from the stage-2 fault inline path. If the
    /// faulting IPA falls inside the GICD MMIO page or any GICR page,
    /// dispatch the access to the vGIC and resume; otherwise return false
    /// so the exit handler forwards the fault to the VMM.
    ///
    /// The aarch64 stage-2 syndrome (ESR_EL2.ISS with ISV=1) already
    /// supplies the access size, target register, and direction — see
    /// 102142 §4.5 — so unlike x64 we do not need to decode the guest
    /// instruction to handle a vGIC MMIO access.
    pub fn tryHandleMmio(self: *Vm, vcpu_obj: *VCpu, fault: vm_hw.VmExitInfo.Stage2Fault) bool {
        const ipa = fault.guest_phys;

        // GICD page.
        if (ipa >= vgic_mod.GICD_BASE and ipa < vgic_mod.GICD_BASE + vgic_mod.GICD_SIZE) {
            const offset = ipa - vgic_mod.GICD_BASE;
            return self.handleVgicMmio(vcpu_obj, offset, fault, .gicd);
        }

        // Per-vCPU GICR pages.
        const gicr_total = vgic_mod.GICR_STRIDE * self.num_vcpus;
        if (ipa >= vgic_mod.GICR_BASE and ipa < vgic_mod.GICR_BASE + gicr_total) {
            const offset = ipa - vgic_mod.GICR_BASE;
            return self.handleVgicMmio(vcpu_obj, offset, fault, .gicr);
        }

        return false;
    }

    const VgicTarget = enum { gicd, gicr };

    fn handleVgicMmio(
        self: *Vm,
        vcpu_obj: *VCpu,
        offset: u64,
        fault: vm_hw.VmExitInfo.Stage2Fault,
        target: VgicTarget,
    ) bool {
        // Without a valid syndrome we cannot decode the access. Forward
        // to VMM in that case so it can do an instruction decode.
        if (!fault.issValid()) return false;

        const size: u8 = @as(u8, 1) << @intCast(fault.access_size);
        if (fault.isWrite()) {
            const value = readGuestGpr(&vcpu_obj.guest_state, fault.srt);
            switch (target) {
                .gicd => vgic_mod.mmioWrite(&self.vgic, &vcpu_obj.vgic_state, offset, size, value),
                .gicr => vgic_mod.mmioWrite(&self.vgic, &vcpu_obj.vgic_state, offset, size, value),
            }
        } else {
            const value = switch (target) {
                .gicd => vgic_mod.mmioRead(&self.vgic, &vcpu_obj.vgic_state, offset, size),
                .gicr => vgic_mod.mmioRead(&self.vgic, &vcpu_obj.vgic_state, offset, size),
            };
            writeGuestGpr(&vcpu_obj.guest_state, fault.srt, value);
        }
        // Advance PC past the faulting instruction. AArch64 instructions
        // are always 4 bytes (ARM ARM B1.2.4). ESR_EL2.IL is informational.
        vcpu_obj.guest_state.pc +%= 4;
        return true;
    }

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
// Syscall implementations
// ---------------------------------------------------------------------------

/// `vm_create` — allocate a VM, its arch structures, and `vcpu_count`
/// vCPU threads. Inserts every vCPU thread handle plus the VM handle into
/// the calling process's perm table.
pub fn vmCreate(proc: *Process, vcpu_count: u32, policy_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_PERM: i64 = -2;
    const E_NOMEM: i64 = -4;
    const E_MAXCAP: i64 = -5;
    const E_BADADDR: i64 = -7;
    const E_NODEV: i64 = -13;

    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().vm_create) return E_PERM;

    if (!vm_hw.vmSupported()) return E_NODEV;

    if (vcpu_count == 0 or vcpu_count > MAX_VCPUS) return E_INVAL;
    if (proc.vm != null) return E_INVAL;

    if (proc.perm_count + vcpu_count + 1 > zag.proc.process.MAX_PERMS) return E_MAXCAP;

    if (policy_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(policy_ptr)) return E_BADADDR;
    var policy_buf: [@sizeOf(vm_hw.VmPolicy)]u8 = undefined;
    if (!readUserStruct(proc, policy_ptr, &policy_buf)) return E_BADADDR;
    const user_policy = std.mem.bytesAsValue(vm_hw.VmPolicy, &policy_buf);

    if (user_policy.num_id_reg_responses > vm_hw.VmPolicy.MAX_ID_REG_RESPONSES) return E_INVAL;
    if (user_policy.num_sysreg_policies > vm_hw.VmPolicy.MAX_SYSREG_POLICIES) return E_INVAL;

    const vm_alloc = slab_instance.create() catch return E_NOMEM;
    const vm_obj = vm_alloc.ptr;

    const arch_structures = stage2.vmAllocStructures() orelse {
        slab_instance.destroy(vm_obj, vm_alloc.gen) catch unreachable;
        return E_NOMEM;
    };

    // Field-by-field init preserves `vm_obj._gen_lock` set by the slab
    // allocator. A `.* = .{...}` would zero it.
    vm_obj.vcpus = undefined;
    vm_obj.num_vcpus = 0;
    vm_obj.owner = slabRefNow(Process, proc);
    vm_obj.exit_box = .{};
    vm_obj.policy = user_policy.*;
    vm_obj.vm_id = @atomicRmw(u64, &vm_id_counter, .Add, 1, .monotonic);
    vm_obj.arch_structures = arch_structures;
    vm_obj.guest_mem = .{};
    vm_obj.guest_ram_host_base = 0;
    vm_obj.guest_ram_size = 0;
    vm_obj.vgic = .{};
    vm_obj.vmid = 0;
    vm_obj.vmid_generation = 0;

    // Hand out a stage-2 VMID. The allocator is idempotent under rollover —
    // every world-switch entry re-validates via `vmid.refresh` — but we
    // still seed the pair eagerly so the first `refresh` is a cheap
    // generation compare rather than a full allocation.
    vmid_mod.allocate(vm_obj);

    // Initialize the in-kernel vGIC distributor for this VM. The vGIC
    // module owns its own state machine; we just hand it a pointer.
    vgic_mod.init(&vm_obj.vgic, vcpu_count);

    // Create vCPUs. Track each inserted perm-table handle so we can
    // roll back on partial failure.
    var inserted_handles: [MAX_VCPUS]u64 = undefined;
    var inserted_count: u32 = 0;
    var i: u32 = 0;
    while (i < vcpu_count) {
        const vcpu_obj = vcpu_mod.create(vm_obj) catch {
            var k: u32 = 0;
            while (k < inserted_count) {
                proc.removePerm(inserted_handles[k]) catch {};
                k += 1;
            }
            // self-alive: slots were allocated in this loop and not freed.
            var j: u32 = 0;
            while (j < i) {
                vcpu_mod.destroy(vm_obj.vcpus[j].ptr, @intCast(vm_obj.vcpus[j].gen));
                j += 1;
            }
            stage2.vmFreeStructures(arch_structures);
            slab_instance.destroy(vm_obj, vm_alloc.gen) catch unreachable;
            return E_NOMEM;
        };

        vm_obj.vcpus[i] = SlabRef(VCpu).init(vcpu_obj, vcpu_obj._gen_lock.currentGen());
        vm_obj.num_vcpus = i + 1;

        // Per-vCPU vGIC state (PPIs + SGIs) needs initializing once the
        // VCpu allocation exists.
        vgic_mod.initVcpu(&vcpu_obj.vgic_state, &vm_obj.vgic, i);
        // Per-vCPU virtual timer save area — zero baseline, CNTVOFF
        // snapshot is taken on first entry by `vtimer.loadGuest`.
        kvm.vtimer.initVcpu(&vcpu_obj.vtimer_state);

        // self-alive: vcpu_obj was just returned by vcpu_mod.create.
        const handle_id = proc.insertThreadHandle(vcpu_obj.thread.ptr, ThreadHandleRights.full) catch {
            var k: u32 = 0;
            while (k < inserted_count) {
                proc.removePerm(inserted_handles[k]) catch {};
                k += 1;
            }
            // self-alive: slots were allocated in this loop and not freed.
            var j: u32 = 0;
            while (j <= i) {
                vcpu_mod.destroy(vm_obj.vcpus[j].ptr, @intCast(vm_obj.vcpus[j].gen));
                j += 1;
            }
            stage2.vmFreeStructures(arch_structures);
            slab_instance.destroy(vm_obj, vm_alloc.gen) catch unreachable;
            return E_MAXCAP;
        };
        inserted_handles[inserted_count] = handle_id;
        inserted_count += 1;
        i += 1;
    }

    proc.vm = slabRefNow(Vm, vm_obj);

    const vm_handle_id = proc.insertPerm(PermissionEntry{
        .handle = 0,
        .object = KernelObject{ .vm = slabRefNow(Vm, vm_obj) },
        .rights = 0xFFFF,
    }) catch {
        var k: u32 = 0;
        while (k < inserted_count) {
            proc.removePerm(inserted_handles[k]) catch {};
            k += 1;
        }
        vm_obj.destroy(vm_alloc.gen);
        return E_MAXCAP;
    };

    return @bitCast(vm_handle_id);
}

/// `vm_guest_map` — wire a host vaddr range into the VM's stage-2 tables.
pub fn guestMap(proc: *Process, vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_NOMEM: i64 = -4;
    const E_BADADDR: i64 = -7;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    if (size == 0) return E_INVAL;
    if (!std.mem.isAligned(guest_addr, 0x1000)) return E_INVAL;
    if (!std.mem.isAligned(size, 0x1000)) return E_INVAL;
    if (rights > 0x7) return E_INVAL;
    if (!std.mem.isAligned(host_vaddr, 0x1000)) return E_INVAL;
    if (!zag.memory.address.AddrSpacePartition.user.contains(host_vaddr)) return E_BADADDR;

    // Reject ranges whose end wraps u64. See x64/kvm/vm.zig commentary
    // for the security justification — same logic applies.
    const guest_end = std.math.add(u64, guest_addr, size) catch return E_INVAL;

    // Reject ranges overlapping the in-kernel vGIC MMIO pages. These are
    // owned by the kernel and must always stage-2-fault to the inline
    // handler — see `Vm.tryHandleMmio`.
    if (guest_addr < vgic_mod.GICD_BASE + vgic_mod.GICD_SIZE and guest_end > vgic_mod.GICD_BASE) return E_INVAL;

    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();

    const gicr_end = vgic_mod.GICR_BASE + vgic_mod.GICR_STRIDE * vm_obj.num_vcpus;
    if (guest_addr < gicr_end and guest_end > vgic_mod.GICR_BASE) return E_INVAL;

    var offset: u64 = 0;
    while (offset < size) {
        const vaddr = VAddr.fromInt(host_vaddr + offset);
        proc.vmm.demandPage(vaddr, false, false) catch {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_BADADDR;
        };
        const host_phys = aarch64_paging.resolveVaddr(proc.addr_space_root, vaddr) orelse {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_BADADDR;
        };
        // M4 #125: `stage2.mapGuestPage` picks stage-2 MemAttr from the
        // target IPA internally (PL011, virtio-mmio → Device-nGnRnE;
        // everything else → Normal WB). vGIC windows never reach this
        // code — `guestMap` rejects them above and `Vm.tryHandleMmio`
        // consumes the resulting stage-2 fault.
        stage2.mapGuestPage(vm_obj.arch_structures, guest_addr + offset, host_phys, @truncate(rights)) catch {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_NOMEM;
        };
        offset += 0x1000;
    }

    vm_obj.guest_mem.addRegion(guest_addr, size, @truncate(rights)) catch {
        rollbackGuestMap(vm_obj, guest_addr, size);
        return E_NOMEM;
    };

    if (vm_obj.guest_ram_host_base == 0 and guest_addr == 0) {
        vm_obj.guest_ram_host_base = host_vaddr;
        vm_obj.guest_ram_size = size;
    }

    return 0; // E_OK
}

fn rollbackGuestMap(vm_obj: *Vm, guest_addr: u64, mapped_size: u64) void {
    var off: u64 = 0;
    while (off < mapped_size) {
        stage2.unmapGuestPage(vm_obj.arch_structures, guest_addr + off);
        off += 0x1000;
    }
}

/// `vm_sysreg_passthrough` — on ARM the `sysreg_id` parameter is a packed
/// (op0,op1,crn,crm,op2) sysreg encoding (see `stage2.sysregPassthrough`
/// header). The kernel refuses security-critical sysregs that would
/// allow the guest to escape EL1 confinement.
pub fn sysregPassthrough(proc: *Process, vm_handle: u64, sysreg_id: u32, allow_read: bool, allow_write: bool) i64 {
    const E_PERM: i64 = -2;
    const E_BADCAP: i64 = -3;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    // Serialize the HCR override RMW — multiple threads in the same
    // process could otherwise race on the VM's control block.
    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();

    stage2.sysregPassthrough(vm_obj.arch_structures, sysreg_id, allow_read, allow_write) catch return E_PERM;
    return 0; // E_OK
}

/// `vm_intc_assert_irq` — assert an SPI line on the in-kernel vGIC.
/// The spec bounds irq_num < 24 for cross-arch parity with the x86 IOAPIC
/// pin count; SPIs in GICv3 are INTID 32..1019, exposed here as
/// `irq_num + 32`.
pub fn intcAssertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;
    if (irq_num >= 24) return E_INVAL;
    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();
    vgic_mod.assertSpi(&vm_obj.vgic, @intCast(irq_num + 32));
    kickRunningVcpus(vm_obj);
    return 0; // E_OK
}

pub fn intcDeassertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;
    if (irq_num >= 24) return E_INVAL;
    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();
    vgic_mod.deassertSpi(&vm_obj.vgic, @intCast(irq_num + 32));
    kickRunningVcpus(vm_obj);
    return 0; // E_OK
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kickRunningVcpus(vm_obj: *Vm) void {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |vcpu_ref| {
        const vcpu_obj = vcpu_ref.lock() catch continue;
        defer vcpu_ref.unlock();
        if (vcpu_obj.loadState() == .running) {
            const thread = vcpu_obj.thread.lock() catch continue;
            defer vcpu_obj.thread.unlock();
            if (sched.coreRunning(thread)) |core_id| {
                gic.sendSchedulerIpi(core_id);
            }
        }
    }
}

/// Resolve a VM handle from the process's perm table. Returns the *Vm or null.
pub fn resolveVmHandle(proc: *Process, vm_handle: u64) ?*Vm {
    const entry = proc.getPermByHandle(vm_handle) orelse return null;
    return switch (entry.object) {
        .vm => |v| v,
        else => null,
    };
}

/// Read a user struct via physmap, handling cross-page boundaries.
pub fn readUserStruct(proc: *Process, user_va: u64, buf: []u8) bool {
    const end = std.math.add(u64, user_va, buf.len) catch return false;
    if (!zag.memory.address.AddrSpacePartition.user.contains(user_va)) return false;
    if (end != user_va and !zag.memory.address.AddrSpacePartition.user.contains(end - 1)) return false;

    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const src_pa = aarch64_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(src_pa, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

/// Read GPR `n` from a guest state. n=31 returns the zero register.
fn readGuestGpr(gs: *const vm_hw.GuestState, n: u8) u64 {
    if (n == 31) return 0; // XZR
    const base: [*]const u64 = @ptrCast(gs);
    return base[n];
}

/// Write GPR `n` into a guest state. n=31 is XZR (write ignored).
fn writeGuestGpr(gs: *vm_hw.GuestState, n: u8, value: u64) void {
    if (n == 31) return;
    const base: [*]u64 = @ptrCast(gs);
    base[n] = value;
}

