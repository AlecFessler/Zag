const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const process_mod = zag.proc.process;
const sched = zag.sched.scheduler;

const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Priority = zag.sched.thread.Priority;
const Process = zag.proc.process.Process;
const ProcessHandleRights = zag.perms.permissions.ProcessHandleRights;
const ProcessRights = zag.perms.permissions.ProcessRights;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;
const VmNode = zag.memory.vmm.VmNode;

const E_BADADDR = errors.E_BADADDR;
const E_BADCAP = errors.E_BADCAP;
const E_BUSY = errors.E_BUSY;
const E_INVAL = errors.E_INVAL;
const E_MAXCAP = errors.E_MAXCAP;
const E_NOMEM = errors.E_NOMEM;
const E_NORES = errors.E_NORES;
const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

pub fn sysProcCreate(elf_ptr: u64, elf_len: u64, perms_arg: u64, thread_rights_arg: u64, max_priority_arg: u64) i64 {
    kprof.enter(.sys_proc_create);
    defer kprof.exit(.sys_proc_create);
    if (elf_len == 0) return E_INVAL;
    if (!address.AddrSpacePartition.user.contains(elf_ptr)) return E_BADADDR;
    const elf_end = std.math.add(u64, elf_ptr, elf_len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(elf_end -| 1)) return E_BADADDR;

    // Validate thread_rights — the upper 3 bits (5-7) are unused.
    // Valid bits are suspend(0), resume(1), kill(2), unpin(3), pmu(4).
    const thr_rights_raw: u8 = @truncate(thread_rights_arg);
    if (thr_rights_raw & 0xE0 != 0) return E_INVAL;
    const thr_rights: ThreadHandleRights = @bitCast(thr_rights_raw);

    if (max_priority_arg > 4) return E_INVAL;
    const child_max_priority: Priority = @enumFromInt(@as(u3, @truncate(max_priority_arg)));

    const proc = sched.currentProc();

    // Verify the entire ELF buffer is backed by mapped VMM nodes with read rights.
    var check_addr = elf_ptr;
    while (check_addr < elf_end) {
        const node_ref: SlabRef(VmNode) = proc.vmm.findNode(VAddr.fromInt(check_addr)) orelse return E_BADADDR;
        const node = node_ref.lock() catch return E_BADADDR;
        const readable = node.rights.read;
        const node_end = node.end();
        node_ref.unlock();
        if (!readable) return E_BADADDR;
        check_addr = node_end;
    }

    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    const parent_self_rights = self_entry.processRights();
    if (!parent_self_rights.spawn_process) return E_PERM;

    if (@intFromEnum(child_max_priority) > @intFromEnum(proc.max_thread_priority)) return E_PERM;

    const child_perms: ProcessRights = @bitCast(@as(u16, @truncate(perms_arg)));
    if (child_perms.restart and proc.restart_context == null) return E_PERM;

    // Child permissions must be a subset of the parent's own process rights.
    const child_bits: u16 = @bitCast(child_perms);
    const parent_bits: u16 = @bitCast(parent_self_rights);
    if (child_bits & ~parent_bits != 0) return E_PERM;

    // Copy ELF buffer into kernel memory to prevent TOCTOU races.
    // Pre-fault every source page first: raw @memcpy from user VA in ring 0
    // would take a page fault on any uncommitted demand-paged page, and
    // interrupts.zig's ring-0-on-user-VA path kills the calling process.
    //
    // Backing comes straight from the PMM as a single contiguous range
    // sized to the next power-of-two that covers `elf_len` — we access
    // it through the kernel physmap, memcpy from user, and `freeBlock`
    // it at the same order when the syscall returns. No kernel heap
    // involvement.
    const elf_num_pages_u64 = std.mem.alignForward(u64, elf_len, paging.PAGE4K) / paging.PAGE4K;
    if (elf_num_pages_u64 == 0 or elf_num_pages_u64 > std.math.maxInt(u32)) return E_NOMEM;
    const elf_rounded_pages = std.math.ceilPowerOfTwo(u32, @intCast(elf_num_pages_u64)) catch return E_NOMEM;
    const elf_alloc_size = @as(u64, elf_rounded_pages) * paging.PAGE4K;

    var pmm_global = &pmm.global_pmm.?;
    const elf_block = pmm_global.allocBlock(elf_alloc_size) orelse return E_NOMEM;
    defer pmm_global.freeBlock(elf_block[0..elf_alloc_size]);
    const elf_copy: []u8 = elf_block[0..elf_len];

    {
        var page_va = std.mem.alignBackward(u64, elf_ptr, paging.PAGE4K);
        while (page_va < elf_end) {
            proc.vmm.demandPage(VAddr.fromInt(page_va), false, false) catch return E_BADADDR;
            page_va += paging.PAGE4K;
        }
    }
    const user_bytes: [*]const u8 = @ptrFromInt(elf_ptr);
    arch.cpu.userAccessBegin();
    @memcpy(elf_copy, user_bytes[0..elf_len]);
    arch.cpu.userAccessEnd();

    const child = Process.create(elf_copy, child_perms, proc, thr_rights, child_max_priority) catch |e| return switch (e) {
        error.InvalidElf => E_INVAL,
        error.OutOfKernelStacks, error.TooManyChildren => E_NORES,
        else => E_NOMEM,
    };

    // Parent's handle to child uses ProcessHandleRights (all rights granted EXCEPT fault_handler;
    // fault_handler is exclusive — only one process can hold it for a given target, and it must
    // be explicitly transferred via HANDLE_SELF cap transfer)
    const parent_rights: u16 = @bitCast(ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    });
    const child_entry = PermissionEntry{
        .handle = 0,
        .object = .{ .process = process_mod.slabRefNow(Process, child) },
        .rights = parent_rights,
    };
    const handle_id = proc.insertPerm(child_entry) catch {
        child.kill(.killed);
        return E_MAXCAP;
    };

    sched.enqueueOnCore(arch.smp.coreID(), child.threads[0]);
    return @intCast(handle_id);
}

pub fn sysRevokePerm(handle: u64) i64 {
    kprof.enter(.sys_revoke_perm);
    defer kprof.exit(.sys_revoke_perm);
    if (handle == 0) return E_INVAL;

    const proc = sched.currentProc();
    const entry = proc.getPermByHandle(handle) orelse return E_BADCAP;

    switch (entry.object) {
        .vm_reservation => |vm_res| {
            proc.vmm.revokeReservation(vm_res.original_start, vm_res.original_size) catch {};
            proc.removePerm(handle) catch {};
        },
        .shared_memory => |shm_ref| {
            const shm = shm_ref.ptr;
            // DMA mappings of this SHM pin the kernel-side `*SharedMemory`
            // via a raw pointer in `proc.dma_mappings` (no counted ref).
            // If we dropped the perm-table ref here while a DMA mapping
            // still pointed at `shm`, `shm.decRef()` could destroy the
            // SharedMemory and free its backing pages while the IOMMU
            // page table still routes device DMA at those phys frames —
            // a device-driven arbitrary-physical-memory write on any
            // frame the PMM subsequently hands out. Refuse the revoke
            // until the caller explicitly `mem_dma_unmap`s the SHM.
            // See exploits/dma_revoke_stale_iommu.
            for (proc.dma_mappings[0..proc.num_dma_mappings]) |*m| {
                if (m.active and m.shm.ptr == shm) return E_BUSY;
            }
            // Remove the handle from the permission table BEFORE freeing
            // the SHM.  This prevents a concurrent sysMemShmMap (which holds
            // perm_lock across its lookup + vmm.mem_shm_map) from finding the
            // entry after the SHM has been freed.
            proc.removePerm(handle) catch {};
            const res = collectReservations(proc);
            proc.vmm.revokeShmHandle(shm, res.items());
            shm.decRef();
        },
        .device_region => |dev_ref| {
            const device = dev_ref.ptr;
            const res = collectReservations(proc);
            proc.vmm.revokeMmioHandle(device, res.items());
            // Remove our slot first so there is no window where both
            // our table and an ancestor's table hold the same device
            // pointer (mirrors SHM revoke ordering above).
            proc.removePerm(handle) catch {};
            Process.returnDeviceHandleUpTree(proc, entry.rights, device);
        },
        .process => |child_ref| {
            const child = child_ref.ptr;
            // §2.12.6: revoking a handle with the fault_handler bit releases
            // the fault-handler relationship without killing the target.
            if (entry.processHandleRights().fault_handler) {
                proc.releaseFaultHandler(child);
            }
            if (entry.processHandleRights().kill) {
                child.killSubtree();
            }
            proc.removePerm(handle) catch {};
        },
        .dead_process => {
            proc.removePerm(handle) catch {};
        },
        .thread => |thread_ref| {
            const t = thread_ref.ptr;
            // If the thread is pinned, release the core pin before removing
            // the handle. Otherwise PerCoreState.pinned_thread is orphaned
            // and that core is deadlocked for preemptive scheduling.
            if (t.priority == .pinned) {
                const core_id = @ctz(t.core_affinity orelse 0);
                sched.unpinByRevoke(core_id);
            }
            proc.removePerm(handle) catch {};
        },
        .vm => |vm_ref| {
            vm_ref.ptr.destroy();
            proc.removePerm(handle) catch {};
        },
        .empty => return E_BADCAP,
    }

    return E_OK;
}

const ReservationCollection = struct {
    buf: [128]VirtualMemoryManager.ReservationInfo = undefined,
    count: usize = 0,

    fn items(self: *const ReservationCollection) []const VirtualMemoryManager.ReservationInfo {
        return self.buf[0..self.count];
    }
};

fn collectReservations(proc: *Process) ReservationCollection {
    var result = ReservationCollection{};
    proc.perm_lock.lock();
    defer proc.perm_lock.unlock();
    for (proc.perm_table) |pe| {
        if (pe.object == .vm_reservation) {
            const vm_res = pe.object.vm_reservation;
            result.buf[result.count] = .{
                .start = vm_res.original_start.addr,
                .end = vm_res.original_start.addr + vm_res.original_size,
                .rights = .{
                    .read = vm_res.max_rights.read,
                    .write = vm_res.max_rights.write,
                    .execute = vm_res.max_rights.execute,
                },
            };
            result.count += 1;
        }
    }
    return result;
}

pub fn sysDisableRestart() i64 {
    const proc = sched.currentProc();
    if (proc.restart_context == null) return E_PERM;
    proc.disableRestart();
    return E_OK;
}
