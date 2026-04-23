const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const kvm = zag.arch.x64.kvm;
const mmio_decode = zag.arch.x64.mmio_decode;
const vm_hw = zag.arch.x64.vm;
const exit_box_mod = kvm.exit_box;
const guest_memory = kvm.guest_memory;
const ioapic_mod = kvm.ioapic;
const lapic_mod = kvm.lapic;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const vcpu_mod = kvm.vcpu;

const GuestMemory = guest_memory.GuestMemory;
const Ioapic = ioapic_mod.Ioapic;
const KernelObject = zag.perms.permissions.KernelObject;
const Lapic = lapic_mod.Lapic;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.proc.process.Process;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SpinLock = zag.utils.sync.SpinLock;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const VAddr = zag.memory.address.VAddr;
const VCpu = vcpu_mod.VCpu;
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
    vcpus: [MAX_VCPUS]*VCpu = undefined,
    num_vcpus: u32 = 0,
    owner: *Process,
    exit_box: VmExitBox = .{},
    policy: vm_hw.VmPolicy = .{},
    lock: SpinLock = .{},
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

    /// Destroy this VM: kill all vCPU threads, free structures.
    pub fn destroy(self: *Vm) void {
        // Kill all vCPU threads
        var i: u32 = 0;
        while (i < self.num_vcpus) {
            vcpu_mod.destroy(self.vcpus[i]);
            i += 1;
        }
        self.num_vcpus = 0;

        // Free guest memory mappings
        self.guest_mem.deinit(self.arch_structures);

        // Free arch-specific structures
        if (self.arch_structures.addr != 0) {
            vm_hw.vmFreeStructures(self.arch_structures);
        }

        // Clear owner's vm pointer
        self.owner.vm = null;

        const gen = VmAllocator.currentGen(self);
        slab_instance.destroy(self, gen) catch unreachable;
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

/// Syscall implementation: create a VM for the calling process.
pub fn vmCreate(proc: *Process, vcpu_count: u32, policy_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_PERM: i64 = -2;
    const E_NOMEM: i64 = -4;
    const E_MAXCAP: i64 = -5;
    const E_BADADDR: i64 = -7;
    const E_NODEV: i64 = -13;

    // Check ProcessRights.vm_create on slot 0
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().vm_create) return E_PERM;

    // Check hardware support
    if (!vm_hw.vmSupported()) return E_NODEV;

    // Validate arguments
    if (vcpu_count == 0 or vcpu_count > MAX_VCPUS) return E_INVAL;
    if (proc.vm != null) return E_INVAL;

    // Check we have room in perm table for all vCPU thread handles + 1 VM handle
    if (proc.perm_count + vcpu_count + 1 > zag.proc.process.MAX_PERMS) return E_MAXCAP;

    // Read policy from userspace via physmap, handling cross-page boundaries.
    if (policy_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(policy_ptr)) return E_BADADDR;
    var policy_buf: [@sizeOf(vm_hw.VmPolicy)]u8 = undefined;
    if (!readUserStruct(proc, policy_ptr, &policy_buf)) return E_BADADDR;
    const user_policy = std.mem.bytesAsValue(vm_hw.VmPolicy, &policy_buf);

    // Reject oversized policy counts -- a malicious VMM could otherwise
    // cause lookupCpuidPolicy/lookupCrPolicy to OOB-read the policy struct.
    if (user_policy.num_cpuid_responses > vm_hw.VmPolicy.MAX_CPUID_POLICIES) return E_INVAL;
    if (user_policy.num_cr_policies > vm_hw.VmPolicy.MAX_CR_POLICIES) return E_INVAL;

    // Allocate VM struct
    const vm_alloc = slab_instance.create() catch return E_NOMEM;
    const vm_obj = vm_alloc.ptr;

    // Allocate arch-specific structures
    const arch_structures = vm_hw.vmAllocStructures() orelse {
        slab_instance.destroy(vm_obj, vm_alloc.gen) catch unreachable;
        return E_NOMEM;
    };

    vm_obj.* = .{
        .owner = proc,
        .policy = user_policy.*,
        .vm_id = @atomicRmw(u64, &vm_id_counter, .Add, 1, .monotonic),
        .arch_structures = arch_structures,
    };

    // Initialize in-kernel LAPIC and IOAPIC emulation. The two devices
    // notify each other through host-callback structs (`LapicHost` /
    // `IoapicHost`) routed via the owning Vm rather than holding typed
    // pointers at each other — that peer coupling was a module-import
    // cycle (see `lapicNotifyLevelEoi` / `ioapicInjectExternal` below).
    vm_obj.ioapic.init(.{
        .ctx = vm_obj,
        .injectExternal = ioapicInjectExternal,
    });
    vm_obj.lapic.init(.{
        .ctx = vm_obj,
        .notifyLevelEoi = lapicNotifyLevelEoi,
    });

    // Create vCPUs. Track each inserted perm-table handle so we can roll
    // back on partial failure without leaking dangling thread handles.
    var inserted_handles: [MAX_VCPUS]u64 = undefined;
    var inserted_count: u32 = 0;
    var i: u32 = 0;
    while (i < vcpu_count) {
        const vcpu_obj = vcpu_mod.create(vm_obj) catch {
            // Cleanup already-inserted handles (before destroying their threads)
            var k: u32 = 0;
            while (k < inserted_count) {
                proc.removePerm(inserted_handles[k]) catch {};
                k += 1;
            }
            // Destroy already-created vCPUs
            var j: u32 = 0;
            while (j < i) {
                vcpu_mod.destroy(vm_obj.vcpus[j]);
                j += 1;
            }
            vm_hw.vmFreeStructures(arch_structures);
            slab_instance.destroy(vm_obj, vm_alloc.gen) catch unreachable;
            return E_NOMEM;
        };

        vm_obj.vcpus[i] = vcpu_obj;
        vm_obj.num_vcpus = i + 1;

        // Insert thread handle into caller's perm table
        const handle_id = proc.insertThreadHandle(vcpu_obj.thread, ThreadHandleRights.full) catch {
            // Cleanup already-inserted handles
            var k: u32 = 0;
            while (k < inserted_count) {
                proc.removePerm(inserted_handles[k]) catch {};
                k += 1;
            }
            // Destroy all vCPUs including the one whose handle failed to insert
            var j: u32 = 0;
            while (j <= i) {
                vcpu_mod.destroy(vm_obj.vcpus[j]);
                j += 1;
            }
            vm_hw.vmFreeStructures(arch_structures);
            slab_instance.destroy(vm_obj, vm_alloc.gen) catch unreachable;
            return E_MAXCAP;
        };
        inserted_handles[inserted_count] = handle_id;
        inserted_count += 1;
        i += 1;
    }

    proc.vm = vm_obj;

    // Insert VM handle into caller's perm table
    const vm_handle_id = proc.insertPerm(PermissionEntry{
        .handle = 0, // will be assigned by insertPerm
        .object = KernelObject{ .vm = vm_obj },
        .rights = 0xFFFF,
    }) catch {
        // Cleanup on failure: remove all vCPU thread handles, destroy VM
        var k: u32 = 0;
        while (k < inserted_count) {
            proc.removePerm(inserted_handles[k]) catch {};
            k += 1;
        }
        vm_obj.destroy();
        return E_MAXCAP;
    };

    return @bitCast(vm_handle_id);
}

/// Syscall implementation: map host virtual memory into guest physical address space (EPT).
pub fn guestMap(proc: *Process, vm_handle: u64, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_NOMEM: i64 = -4;
    const E_BADADDR: i64 = -7;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    if (size == 0) return E_INVAL;
    if (!std.mem.isAligned(guest_addr, 0x1000)) return E_INVAL;
    if (!std.mem.isAligned(size, 0x1000)) return E_INVAL;
    if (rights > 0x7) return E_INVAL; // only read/write/execute bits
    if (!std.mem.isAligned(host_vaddr, 0x1000)) return E_INVAL;
    if (!zag.memory.address.AddrSpacePartition.user.contains(host_vaddr)) return E_BADADDR;

    // Reject any (guest_addr, size) whose sum wraps u64. Without this
    // check:
    //   - In safety-checked builds, `guest_addr + size` below panics
    //     the kernel from unprivileged userspace (single-syscall DoS
    //     reachable by any process with vm_create rights).
    //   - In unchecked builds, the sum wraps and folds a wrapping
    //     range down into a small inner `guest_end`, so the
    //     LAPIC/IOAPIC overlap check below can return false even when
    //     the wrap-covered range includes one of those pages. The
    //     recorded GuestMemory region would also have
    //     guest_phys_start + size > 2^64, which deinit then sweeps by
    //     wrapping into unrelated guest-phys pages.
    const guest_end = std.math.add(u64, guest_addr, size) catch return E_INVAL;

    // Guard LAPIC and IOAPIC pages -- these are handled in-kernel and
    // must always NPT-fault to the kernel exit handler. Proper interval
    // overlap check: [guest_addr, guest_end) vs [base, base+0x1000).
    if (guest_addr < LAPIC_BASE + 0x1000 and guest_end > LAPIC_BASE) return E_INVAL;
    if (guest_addr < IOAPIC_BASE + 0x1000 and guest_end > IOAPIC_BASE) return E_INVAL;

    // Walk host pages and map each into guest EPT. Track progress for
    // rollback on partial failure.
    var offset: u64 = 0;
    while (offset < size) {
        const vaddr = VAddr.fromInt(host_vaddr + offset);
        // Pre-fault demand-paged host pages before resolving their physical address.
        proc.vmm.demandPage(vaddr, false, false) catch {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_BADADDR;
        };
        const host_phys = arch_paging.resolveVaddr(proc.addr_space_root, vaddr) orelse {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_BADADDR;
        };
        vm_hw.mapGuestPage(vm_obj.arch_structures, guest_addr + offset, host_phys, @truncate(rights)) catch {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_NOMEM;
        };
        offset += 0x1000;
    }

    // Record the region only after all pages are successfully mapped.
    vm_obj.guest_mem.addRegion(guest_addr, size, @truncate(rights)) catch {
        rollbackGuestMap(vm_obj, guest_addr, size);
        return E_NOMEM;
    };

    // Track the main guest RAM region for MMIO instruction decode.
    // First vm_guest_map at guest_addr=0 is typically the main RAM region.
    if (vm_obj.guest_ram_host_base == 0 and guest_addr == 0) {
        vm_obj.guest_ram_host_base = host_vaddr;
        vm_obj.guest_ram_size = size;
    }

    return 0; // E_OK
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
/// calling process's VM. On x86 a "sysreg" is an MSR — `sysreg_id` is the
/// 32-bit MSR address. Modifies MSRPM bits in the VMCB. Refuses
/// security-critical MSRs.
pub fn sysregPassthrough(proc: *Process, vm_handle: u64, sysreg_id: u32, allow_read: bool, allow_write: bool) i64 {
    const E_BADCAP: i64 = -3;
    const E_PERM: i64 = -2;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    // Refuse security-critical MSRs that must always be intercepted.
    if (isSecurityCriticalSysreg(sysreg_id)) return E_PERM;

    // Serialize the MSRPM bitwise RMW -- multiple threads in the same
    // process could otherwise race.
    vm_obj.lock.lock();
    defer vm_obj.lock.unlock();

    // Access the MSRPM via the VMCB.
    vm_hw.sysregPassthrough(vm_obj.arch_structures, sysreg_id, allow_read, allow_write);
    return 0; // E_OK
}

/// Syscall implementation: assert an IRQ line on the in-kernel interrupt
/// controller (x86: IOAPIC).
pub fn intcAssertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;
    if (irq_num >= 24) return E_INVAL;
    vm_obj.ioapic.assertIrq(@truncate(irq_num));
    kickRunningVcpus(vm_obj);
    return 0; // E_OK
}

/// Syscall implementation: de-assert an IRQ line on the in-kernel interrupt
/// controller (x86: IOAPIC).
pub fn intcDeassertIrq(proc: *Process, vm_handle: u64, irq_num: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;
    if (irq_num >= 24) return E_INVAL;
    vm_obj.ioapic.deassertIrq(@truncate(irq_num));
    kickRunningVcpus(vm_obj);
    return 0; // E_OK
}

/// Send an IPI to any core currently running a vCPU thread for this VM,
/// forcing a VMEXIT so the vCPU re-enters VMRUN and checks pending interrupts.
fn kickRunningVcpus(vm_obj: *Vm) void {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |vcpu_obj| {
        if (vcpu_obj.loadState() == .running) {
            if (sched.coreRunning(vcpu_obj.thread)) |core_id| {
                apic.sendSchedulerIpi(core_id);
            }
        }
    }
}

/// Resolve a VM handle from the process's perm table. Returns the *Vm or null.
fn resolveVmHandle(proc: *Process, vm_handle: u64) ?*Vm {
    const entry = proc.getPermByHandle(vm_handle) orelse return null;
    return switch (entry.object) {
        .vm => |v| v,
        else => null,
    };
}

/// Read a struct from userspace into a kernel buffer, handling cross-page boundaries.
fn readUserStruct(proc: *Process, user_va: u64, buf: []u8) bool {
    // Enforce full-range user-partition membership locally. The
    // per-page walk below advances `src_va` across page boundaries
    // without re-checking, and the point check at the caller is not
    // enough to keep a near-top-of-user buffer from spilling into
    // the kernel half.
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
        const page_paddr = arch_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
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
