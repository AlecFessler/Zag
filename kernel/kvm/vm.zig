const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const vcpu_mod = zag.kvm.vcpu;

const Ioapic = zag.kvm.ioapic.Ioapic;
const Lapic = zag.kvm.lapic.Lapic;
const PAddr = zag.memory.address.PAddr;
const Process = zag.sched.process.Process;
const VAddr = zag.memory.address.VAddr;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const VCpu = vcpu_mod.VCpu;
const VmExitBox = zag.kvm.exit_box.VmExitBox;

pub const MAX_VCPUS = 64;

pub const VmAllocator = SlabAllocator(Vm, false, 0, 64, true);

pub var allocator: std.mem.Allocator = undefined;

var vm_id_counter: u64 = 1;

pub const Vm = struct {
    vcpus: [MAX_VCPUS]*VCpu = undefined,
    num_vcpus: u32 = 0,
    owner: *Process,
    exit_box: VmExitBox = .{},
    policy: arch.VmPolicy = .{},
    lock: SpinLock = .{},
    vm_id: u64 = 0,
    arch_structures: PAddr = PAddr.fromInt(0),
    guest_mem: zag.kvm.guest_memory.GuestMemory = .{},
    /// Host virtual base and size of the main guest RAM region (from first guest_map).
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
        while (i < self.num_vcpus) : (i += 1) {
            vcpu_mod.destroy(self.vcpus[i]);
        }
        self.num_vcpus = 0;

        // Free guest memory mappings
        self.guest_mem.deinit(self.arch_structures);

        // Free arch-specific structures
        if (self.arch_structures.addr != 0) {
            arch.vmFreeStructures(self.arch_structures);
        }

        // Clear owner's vm pointer
        self.owner.vm = null;

        allocator.destroy(self);
    }
};

/// Syscall implementation: create a VM for the calling process.
pub fn vmCreate(proc: *Process, vcpu_count: u32, policy_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_NOMEM: i64 = -4;
    const E_MAXCAP: i64 = -5;
    const E_BADADDR: i64 = -7;
    const E_NODEV: i64 = -13;

    // Check hardware support
    if (!arch.vmSupported()) return E_NODEV;

    // Validate arguments
    if (vcpu_count == 0 or vcpu_count > MAX_VCPUS) return E_INVAL;
    if (proc.vm != null) return E_INVAL;

    // Check we have room in perm table for all vCPU thread handles
    if (proc.perm_count + vcpu_count > zag.sched.process.MAX_PERMS) return E_MAXCAP;

    // Read policy from userspace via physmap, handling cross-page boundaries.
    if (policy_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(policy_ptr)) return E_BADADDR;
    var policy_buf: [@sizeOf(arch.VmPolicy)]u8 = undefined;
    if (!readUserStruct(proc, policy_ptr, &policy_buf)) return E_BADADDR;
    const user_policy = std.mem.bytesAsValue(arch.VmPolicy, &policy_buf);

    // Allocate VM struct
    const vm_obj = allocator.create(Vm) catch return E_NOMEM;

    // Allocate arch-specific structures
    const arch_structures = arch.vmAllocStructures() orelse {
        allocator.destroy(vm_obj);
        return E_NOMEM;
    };

    vm_obj.* = .{
        .owner = proc,
        .policy = user_policy.*,
        .vm_id = @atomicRmw(u64, &vm_id_counter, .Add, 1, .monotonic),
        .arch_structures = arch_structures,
    };

    // Initialize in-kernel LAPIC and IOAPIC emulation.
    // IOAPIC needs a pointer to LAPIC for interrupt delivery;
    // LAPIC needs a pointer to IOAPIC for EOI notification.
    vm_obj.ioapic.init(&vm_obj.lapic);
    vm_obj.lapic.init(&vm_obj.ioapic);

    // Create vCPUs
    var i: u32 = 0;
    while (i < vcpu_count) : (i += 1) {
        const vcpu_obj = vcpu_mod.create(vm_obj) catch {
            // Cleanup already-created vCPUs
            var j: u32 = 0;
            while (j < i) : (j += 1) {
                vcpu_mod.destroy(vm_obj.vcpus[j]);
            }
            arch.vmFreeStructures(arch_structures);
            allocator.destroy(vm_obj);
            return E_NOMEM;
        };

        vm_obj.vcpus[i] = vcpu_obj;
        vm_obj.num_vcpus = i + 1;

        // Insert thread handle into caller's perm table
        _ = proc.insertThreadHandle(vcpu_obj.thread, ThreadHandleRights.full) catch {
            // Cleanup
            var j: u32 = 0;
            while (j <= i) : (j += 1) {
                vcpu_mod.destroy(vm_obj.vcpus[j]);
            }
            arch.vmFreeStructures(arch_structures);
            allocator.destroy(vm_obj);
            return E_MAXCAP;
        };
    }

    proc.vm = vm_obj;
    return 0; // E_OK
}

/// Syscall implementation: destroy the calling process's VM.
pub fn vmDestroy(proc: *Process) i64 {
    const E_INVAL: i64 = -1;

    const vm_obj = proc.vm orelse return E_INVAL;
    vm_obj.destroy();
    return 0; // E_OK
}

/// Syscall implementation: map host virtual memory into guest physical address space (EPT).
pub fn guestMap(proc: *Process, host_vaddr: u64, guest_addr: u64, size: u64, rights: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_NOMEM: i64 = -4;
    const E_BADADDR: i64 = -7;

    const vm_obj = proc.vm orelse return E_INVAL;

    if (size == 0) return E_INVAL;
    if (!std.mem.isAligned(guest_addr, 0x1000)) return E_INVAL;
    if (!std.mem.isAligned(size, 0x1000)) return E_INVAL;
    if (rights > 0x7) return E_INVAL; // only read/write/execute bits
    if (!std.mem.isAligned(host_vaddr, 0x1000)) return E_INVAL;
    if (!zag.memory.address.AddrSpacePartition.user.contains(host_vaddr)) return E_BADADDR;

    // Guard LAPIC and IOAPIC pages -- these are handled in-kernel and
    // must always NPT-fault to the kernel exit handler.
    const guest_end = guest_addr + size;
    const lapic_base: u64 = 0xFEE00000;
    const ioapic_base: u64 = 0xFEC00000;
    if (guest_addr <= lapic_base and guest_end > lapic_base) return E_INVAL;
    if (guest_addr <= ioapic_base and guest_end > ioapic_base) return E_INVAL;

    // Walk host pages and map each into guest EPT. Track progress for
    // rollback on partial failure.
    var offset: u64 = 0;
    while (offset < size) : (offset += 0x1000) {
        const vaddr = VAddr.fromInt(host_vaddr + offset);
        // Pre-fault demand-paged host pages before resolving their physical address.
        proc.vmm.demandPage(vaddr, false, false) catch {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_BADADDR;
        };
        const host_phys = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_BADADDR;
        };
        arch.mapGuestPage(vm_obj.arch_structures, guest_addr + offset, host_phys, @truncate(rights)) catch {
            rollbackGuestMap(vm_obj, guest_addr, offset);
            return E_NOMEM;
        };
    }

    // Record the region only after all pages are successfully mapped.
    vm_obj.guest_mem.addRegion(guest_addr, size, @truncate(rights)) catch {
        rollbackGuestMap(vm_obj, guest_addr, size);
        return E_NOMEM;
    };

    // Track the main guest RAM region for MMIO instruction decode.
    // First guest_map at guest_addr=0 is typically the main RAM region.
    if (vm_obj.guest_ram_host_base == 0 and guest_addr == 0) {
        vm_obj.guest_ram_host_base = host_vaddr;
        vm_obj.guest_ram_size = size;
    }

    return 0; // E_OK
}

/// Unmap pages that were successfully mapped during a partial guestMap.
fn rollbackGuestMap(vm_obj: *Vm, guest_addr: u64, mapped_size: u64) void {
    var off: u64 = 0;
    while (off < mapped_size) : (off += 0x1000) {
        arch.unmapGuestPage(vm_obj.arch_structures, guest_addr + off);
    }
}

/// Syscall implementation: allow/deny MSR passthrough for the calling process's VM.
/// Modifies MSRPM bits in the VMCB. Refuses security-critical MSRs.
pub fn msrPassthrough(proc: *Process, msr_num: u32, allow_read: bool, allow_write: bool) i64 {
    const E_INVAL: i64 = -1;
    const E_PERM: i64 = -2;

    const vm_obj = proc.vm orelse return E_INVAL;

    // Refuse security-critical MSRs that must always be intercepted.
    if (isSecurityCriticalMsr(msr_num)) return E_PERM;

    // Access the MSRPM via the VMCB.
    arch.vmMsrPassthrough(vm_obj.arch_structures, msr_num, allow_read, allow_write);
    return 0; // E_OK
}

/// Syscall implementation: assert an IRQ line on the in-kernel IOAPIC.
pub fn ioapicAssertIrq(proc: *Process, irq_num: u64) i64 {
    const E_INVAL: i64 = -1;

    const vm_obj = proc.vm orelse return E_INVAL;
    if (irq_num >= 24) return E_INVAL;
    vm_obj.ioapic.assertIrq(@truncate(irq_num));
    kickRunningVcpus(vm_obj);
    return 0; // E_OK
}

/// Syscall implementation: de-assert an IRQ line on the in-kernel IOAPIC.
pub fn ioapicDeassertIrq(proc: *Process, irq_num: u64) i64 {
    const E_INVAL: i64 = -1;

    const vm_obj = proc.vm orelse return E_INVAL;
    if (irq_num >= 24) return E_INVAL;
    vm_obj.ioapic.deassertIrq(@truncate(irq_num));
    kickRunningVcpus(vm_obj);
    return 0; // E_OK
}

/// Send an IPI to any core currently running a vCPU thread for this VM,
/// forcing a VMEXIT so the vCPU re-enters VMRUN and checks pending interrupts.
fn kickRunningVcpus(vm_obj: *Vm) void {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus]) |vcpu_obj| {
        if (vcpu_obj.state == .running) {
            if (sched.coreRunning(vcpu_obj.thread)) |core_id| {
                arch.triggerSchedulerInterrupt(core_id);
            }
        }
    }
}

/// Returns true if the MSR is security-critical and must always be intercepted.
fn isSecurityCriticalMsr(msr: u32) bool {
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

/// Read a struct from userspace into a kernel buffer, handling cross-page boundaries.
fn readUserStruct(proc: *Process, user_va: u64, buf: []u8) bool {
    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}
