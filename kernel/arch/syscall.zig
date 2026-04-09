const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const futex = zag.sched.futex;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.sched.process.Process;
const memory_init = zag.memory.init;
const process_mod = zag.sched.process;
const FaultReason = zag.perms.permissions.FaultReason;
const KernelObject = zag.perms.permissions.KernelObject;
const ProcessHandleRights = zag.perms.permissions.ProcessHandleRights;
const ProcessRights = zag.perms.permissions.ProcessRights;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const SharedMemory = zag.memory.shared.SharedMemory;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;
const VmReservationRights = zag.perms.permissions.VmReservationRights;

const E_OK: i64 = 0;
const E_INVAL: i64 = -1;
const E_PERM: i64 = -2;
const E_BADCAP: i64 = -3;
const E_NOMEM: i64 = -4;
const E_MAXCAP: i64 = -5;
const E_MAXTHREAD: i64 = -6;
const E_BADADDR: i64 = -7;
const E_TIMEOUT: i64 = -8;
const E_AGAIN: i64 = -9;
const E_NOENT: i64 = -10;
const E_BUSY: i64 = -11;
const E_EXIST: i64 = -12;
const E_NODEV: i64 = -13;
const E_NORES: i64 = -14;

pub const SyscallResult = struct {
    rax: i64,
    rdx: u64 = 0,
};

pub const SyscallNum = enum(u64) {
    write,
    vm_reserve,
    vm_perms,
    shm_create,
    shm_map,
    shm_unmap,
    mmio_map,
    mmio_unmap,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    set_affinity,
    revoke_perm,
    disable_restart,
    futex_wait,
    futex_wake,
    clock_gettime,
    ioport_read,
    ioport_write,
    dma_map,
    dma_unmap,
    pin_exclusive,
    ipc_send,
    ipc_call,
    ipc_recv,
    ipc_reply,
    shutdown,
    thread_self,
    thread_suspend,
    thread_resume,
    thread_kill,
    fault_recv,
    fault_reply,
    fault_read_mem,
    fault_write_mem,
    fault_set_thread_mode,
    _,
};

fn currentProc() *Process {
    return sched.currentThread().?.process;
}

fn isSubset(requested: u16, allowed: u16) bool {
    return (requested & ~allowed) == 0;
}

pub fn dispatch(ctx: *ArchCpuContext) SyscallResult {
    const num = ctx.regs.rax;
    const arg0 = ctx.regs.rdi;
    const arg1 = ctx.regs.rsi;
    const arg2 = ctx.regs.rdx;
    const arg3 = ctx.regs.r10;
    const syscall_num: SyscallNum = @enumFromInt(num);
    return switch (syscall_num) {
        .write => sysWrite(arg0, arg1),
        .vm_reserve => sysVmReserve(arg0, arg1, arg2),
        .vm_perms => .{ .rax = sysVmPerms(arg0, arg1, arg2, arg3) },
        .shm_create => .{ .rax = sysShmCreate(arg0, arg1) },
        .shm_map => .{ .rax = sysShmMap(arg0, arg1, arg2) },
        .shm_unmap => .{ .rax = sysShmUnmap(arg0, arg1) },
        .mmio_map => .{ .rax = sysMmioMap(arg0, arg1, arg2) },
        .mmio_unmap => .{ .rax = sysMmioUnmap(arg0, arg1) },
        .proc_create => .{ .rax = sysProcCreate(arg0, arg1, arg2, arg3) },
        .thread_create => .{ .rax = sysThreadCreate(arg0, arg1, arg2) },
        .thread_exit => sysThreadExit(),
        .thread_yield => .{ .rax = sysThreadYield() },
        .set_affinity => .{ .rax = sysSetAffinity(arg0, arg1) },
        .revoke_perm => .{ .rax = sysRevokePerm(arg0) },
        .disable_restart => .{ .rax = sysDisableRestart() },
        .futex_wait => .{ .rax = sysFutexWait(arg0, arg1, arg2) },
        .futex_wake => .{ .rax = sysFutexWake(arg0, arg1) },
        .clock_gettime => .{ .rax = sysClockGettime() },
        .ioport_read => .{ .rax = sysIoportRead(arg0, arg1, arg2) },
        .ioport_write => .{ .rax = sysIoportWrite(arg0, arg1, arg2, arg3) },
        .dma_map => .{ .rax = sysDmaMap(arg0, arg1) },
        .dma_unmap => .{ .rax = sysDmaUnmap(arg0, arg1) },
        .pin_exclusive => .{ .rax = sysPinExclusive(arg0) },
        .ipc_send => sysIpcSend(ctx),
        .ipc_call => sysIpcCall(ctx),
        .ipc_recv => sysIpcRecv(ctx),
        .ipc_reply => sysIpcReply(ctx),
        .shutdown => sysShutdown(),
        .thread_self => .{ .rax = sysThreadSelf() },
        .thread_suspend => .{ .rax = sysThreadSuspend(arg0) },
        .thread_resume => .{ .rax = sysThreadResume(arg0) },
        .thread_kill => .{ .rax = sysThreadKill(arg0) },
        .fault_recv => .{ .rax = sysFaultRecv(arg0, arg1) },
        .fault_reply => .{ .rax = sysFaultReply(arg0, arg1, arg2) },
        .fault_read_mem => .{ .rax = sysFaultReadMem(arg0, arg1, arg2, arg3) },
        .fault_write_mem => .{ .rax = sysFaultWriteMem(arg0, arg1, arg2, arg3) },
        .fault_set_thread_mode => .{ .rax = sysFaultSetThreadMode(arg0, arg1) },
        _ => .{ .rax = E_INVAL },
    };
}

fn sysWrite(ptr: u64, len: u64) SyscallResult {
    if (len == 0) return .{ .rax = 0 };
    if (len > 4096) return .{ .rax = E_INVAL };
    if (!address.AddrSpacePartition.user.contains(ptr)) return .{ .rax = E_BADADDR };
    const end = std.math.add(u64, ptr, len) catch return .{ .rax = E_BADADDR };
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return .{ .rax = E_BADADDR };
    const msg: []const u8 = @as([*]const u8, @ptrFromInt(ptr))[0..len];
    arch.print("{s}", .{msg});
    return .{ .rax = @intCast(len) };
}

fn sysVmReserve(hint: u64, size: u64, max_perms_bits: u64) SyscallResult {
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return .{ .rax = E_INVAL };

    const max_rights: VmReservationRights = @bitCast(@as(u8, @truncate(max_perms_bits)));
    if (max_rights.shareable and max_rights.mmio) return .{ .rax = E_INVAL };
    if (max_rights.write_combining and !max_rights.mmio) return .{ .rax = E_INVAL };

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return .{ .rax = E_PERM };
    if (!self_entry.processRights().mem_reserve) return .{ .rax = E_PERM };

    const result = proc.vmm.reserve(VAddr.fromInt(hint), size, max_rights) catch return .{ .rax = E_NOMEM };

    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .vm_reservation = .{
            .max_rights = max_rights,
            .original_start = result.vaddr,
            .original_size = size,
        } },
        .rights = @truncate(max_perms_bits),
    };
    const handle_id = proc.insertPerm(entry) catch return .{ .rax = E_MAXCAP };
    result.node.handle = handle_id;

    return .{ .rax = @intCast(handle_id), .rdx = result.vaddr.addr };
}

fn sysVmPerms(vm_handle: u64, offset: u64, size: u64, perms_bits: u64) i64 {
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return E_INVAL;

    const new_rights: VmReservationRights = @bitCast(@as(u8, @truncate(perms_bits)));
    if (new_rights.shareable or new_rights.mmio) return E_INVAL;

    const proc = currentProc();
    const entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = entry.object.vm_reservation;

    const new_rwx = @as(u16, @truncate(perms_bits)) & 0b111;
    const max_rwx =
        @as(u16, @intFromBool(vm_res.max_rights.read)) |
        (@as(u16, @intFromBool(vm_res.max_rights.write)) << 1) |
        (@as(u16, @intFromBool(vm_res.max_rights.execute)) << 2);
    if (!isSubset(new_rwx, max_rwx)) return E_PERM;

    const range_end = std.math.add(u64, offset, size) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.vm_perms(
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        size,
        new_rights,
    ) catch return E_INVAL;

    return E_OK;
}

fn sysShmCreate(size: u64, rights_bits: u64) i64 {
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) {
        return E_INVAL;
    }
    if (rights_bits == 0) return E_INVAL;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse {
        return E_PERM;
    };
    if (!self_entry.processRights().shm_create) {
        return E_PERM;
    }

    const shm = SharedMemory.create(size) catch {
        return E_NOMEM;
    };

    const rights: u16 = @truncate(rights_bits);
    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .shared_memory = shm },
        .rights = rights,
    };
    const handle_id = proc.insertPerm(entry) catch {
        shm.decRef();
        return E_MAXCAP;
    };

    return @intCast(handle_id);
}

fn sysShmMap(shm_handle: u64, vm_handle: u64, offset: u64) i64 {
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;

    const proc = currentProc();

    // Hold perm_lock across both lookups and the vmm.shm_map call to
    // prevent a concurrent revoke_perm from freeing the SharedMemory
    // while we are using its pointer.  Without this, there is a UAF:
    // the revoke frees the SHM between getPermByHandle and vmm.shm_map.
    //
    // Lock ordering: perm_lock → vmm.lock is safe because no code path
    // acquires vmm.lock before perm_lock.
    proc.perm_lock.lock();
    defer proc.perm_lock.unlock();

    const shm_entry = proc.getPermByHandleLocked(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;

    const vm_entry = proc.getPermByHandleLocked(vm_handle) orelse return E_BADCAP;
    if (vm_entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = vm_entry.object.vm_reservation;
    if (!vm_res.max_rights.shareable) return E_PERM;

    const shm = shm_entry.object.shared_memory;
    const shm_rwx = shm_entry.rights & 0b111;
    const max_rwx: u16 =
        @as(u16, @intFromBool(vm_res.max_rights.read)) |
        (@as(u16, @intFromBool(vm_res.max_rights.write)) << 1) |
        (@as(u16, @intFromBool(vm_res.max_rights.execute)) << 2);
    if (!isSubset(shm_rwx, max_rwx)) return E_PERM;

    const shm_map_rights = VmReservationRights{
        .read = shm_entry.shmRights().read,
        .write = shm_entry.shmRights().write,
        .execute = shm_entry.shmRights().execute,
    };

    const range_end = std.math.add(u64, offset, shm.size()) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.shm_map(
        shm_handle,
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        shm,
        shm_map_rights,
    ) catch |e| return switch (e) {
        error.CommittedPages => E_EXIST,
        else => E_INVAL,
    };

    return E_OK;
}

fn sysShmUnmap(shm_handle: u64, vm_handle: u64) i64 {
    const proc = currentProc();

    const shm_entry = proc.getPermByHandle(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;

    const vm_entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (vm_entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = vm_entry.object.vm_reservation;
    const shm = shm_entry.object.shared_memory;

    proc.vmm.shm_unmap(shm, vm_handle, vm_res.original_start, vm_res.original_size, vm_res.max_rights) catch return E_NOENT;

    return E_OK;
}

fn sysMmioMap(device_handle: u64, vm_handle: u64, offset: u64) i64 {
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;

    const proc = currentProc();

    const device_entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (device_entry.object != .device_region) return E_BADCAP;
    if (!device_entry.deviceRights().map) return E_PERM;
    if (device_entry.object.device_region.device_type != .mmio) return E_INVAL;

    const vm_entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (vm_entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = vm_entry.object.vm_reservation;
    if (!vm_res.max_rights.mmio or !vm_res.max_rights.read or !vm_res.max_rights.write) return E_PERM;

    const device = device_entry.object.device_region;

    const range_end = std.math.add(u64, offset, device.access.mmio.size) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.mmio_map(
        device_handle,
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        device,
        vm_res.max_rights.write_combining,
    ) catch |e| return switch (e) {
        error.CommittedPages => E_EXIST,
        else => E_INVAL,
    };

    return E_OK;
}

fn sysMmioUnmap(device_handle: u64, vm_handle: u64) i64 {
    const proc = currentProc();

    const device_entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (device_entry.object != .device_region) return E_BADCAP;

    const vm_entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (vm_entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = vm_entry.object.vm_reservation;
    const device = device_entry.object.device_region;

    proc.vmm.mmio_unmap(device, vm_handle, vm_res.original_start, vm_res.original_size, vm_res.max_rights) catch return E_NOENT;

    return E_OK;
}

fn sysProcCreate(elf_ptr: u64, elf_len: u64, perms_arg: u64, thread_rights_arg: u64) i64 {
    if (elf_len == 0) return E_INVAL;
    if (!address.AddrSpacePartition.user.contains(elf_ptr)) return E_BADADDR;
    const elf_end = std.math.add(u64, elf_ptr, elf_len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(elf_end -| 1)) return E_BADADDR;

    // Validate thread_rights — upper 4 bits must be 0
    const thr_rights_raw: u8 = @truncate(thread_rights_arg);
    if (thr_rights_raw & 0xF0 != 0) return E_INVAL;
    const thr_rights: ThreadHandleRights = @bitCast(thr_rights_raw);

    const proc = currentProc();

    // Verify the entire ELF buffer is backed by mapped VMM nodes with read rights.
    var check_addr = elf_ptr;
    while (check_addr < elf_end) {
        const node = proc.vmm.findNode(VAddr.fromInt(check_addr)) orelse return E_BADADDR;
        if (!node.rights.read) return E_BADADDR;
        check_addr = node.end();
    }

    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    const parent_self_rights = self_entry.processRights();
    if (!parent_self_rights.spawn_process) return E_PERM;

    const child_perms: ProcessRights = @bitCast(@as(u16, @truncate(perms_arg)));
    if (child_perms.restart and proc.restart_context == null) return E_PERM;

    // Child permissions must be a subset of the parent's own process rights.
    const child_bits: u16 = @bitCast(child_perms);
    const parent_bits: u16 = @bitCast(parent_self_rights);
    if (child_bits & ~parent_bits != 0) return E_PERM;

    // Copy ELF buffer into kernel memory to prevent TOCTOU races.
    const kernel_alloc = memory_init.heap_allocator;
    const elf_copy = kernel_alloc.alloc(u8, elf_len) catch return E_NOMEM;
    defer kernel_alloc.free(elf_copy);
    const user_bytes: [*]const u8 = @ptrFromInt(elf_ptr);
    @memcpy(elf_copy, user_bytes[0..elf_len]);

    const child = Process.create(elf_copy, child_perms, proc, thr_rights) catch |e| return switch (e) {
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
        .object = .{ .process = child },
        .rights = parent_rights,
    };
    const handle_id = proc.insertPerm(child_entry) catch {
        child.kill(.killed);
        return E_MAXCAP;
    };

    sched.enqueueOnCore(arch.coreID(), child.threads[0]);
    return @intCast(handle_id);
}

fn sysThreadCreate(entry_addr: u64, arg: u64, num_stack_pages_u64: u64) i64 {
    if (num_stack_pages_u64 == 0 or num_stack_pages_u64 > std.math.maxInt(u32)) return E_INVAL;
    const num_stack_pages: u32 = @intCast(num_stack_pages_u64);

    if (!address.AddrSpacePartition.user.contains(entry_addr)) return E_BADADDR;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().spawn_thread) return E_PERM;

    const thread = Thread.create(proc, VAddr.fromInt(entry_addr), arg, num_stack_pages) catch |e| return switch (e) {
        error.MaxThreads => E_MAXTHREAD,
        error.OutOfKernelStacks => E_NORES,
        else => E_NOMEM,
    };

    // Insert thread handle into process perm table
    const handle_id = proc.insertThreadHandle(thread, proc.thread_handle_rights) catch {
        thread.deinit();
        return E_MAXCAP;
    };

    // If external fault handler, also insert into handler's perm table
    if (proc.fault_handler_proc) |handler| {
        _ = handler.insertThreadHandle(thread, ThreadHandleRights.full) catch {};
    }

    sched.enqueueOnCore(arch.coreID(), thread);
    return @intCast(handle_id);
}

fn sysShutdown() noreturn {
    arch.shutdown();
}

fn sysThreadExit() noreturn {
    const thread = sched.currentThread().?;
    thread.state = .exited;
    arch.enableInterrupts();
    sched.yield();
    while (true) {
        arch.enableInterrupts();
        asm volatile ("hlt");
    }
}

fn sysThreadYield() i64 {
    arch.enableInterrupts();
    sched.yield();
    return E_OK;
}

fn sysSetAffinity(thread_handle: u64, core_mask: u64) i64 {
    if (core_mask == 0) return E_INVAL;
    const count = arch.coreCount();
    const valid_mask: u64 = if (count >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(count)) - 1;
    if (core_mask & ~valid_mask != 0) return E_INVAL;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().set_affinity) return E_PERM;

    // Look up thread handle
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().set_affinity) return E_PERM;

    thr_entry.object.thread.core_affinity = core_mask;
    return E_OK;
}

fn sysRevokePerm(handle: u64) i64 {
    if (handle == 0) return E_INVAL;

    const proc = currentProc();
    const entry = proc.getPermByHandle(handle) orelse return E_BADCAP;

    switch (entry.object) {
        .vm_reservation => |vm_res| {
            proc.vmm.revokeReservation(vm_res.original_start, vm_res.original_size) catch {};
            proc.removePerm(handle) catch {};
        },
        .shared_memory => |shm| {
            // Remove the handle from the permission table BEFORE freeing
            // the SHM.  This prevents a concurrent sysShmMap (which holds
            // perm_lock across its lookup + vmm.shm_map) from finding the
            // entry after the SHM has been freed.
            proc.removePerm(handle) catch {};
            const res = collectReservations(proc);
            proc.vmm.revokeShmHandle(shm, res.items());
            shm.decRef();
        },
        .device_region => |device| {
            const res = collectReservations(proc);
            proc.vmm.revokeMmioHandle(device, res.items());
            Process.returnDeviceHandleUpTree(proc, entry.rights, device);
            proc.removePerm(handle) catch {};
        },
        .core_pin => |cp| {
            sched.unpinByRevoke(cp.core_id, cp.thread_tid);
            proc.removePerm(handle) catch {};
        },
        .process => |child| {
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
        .thread => {
            // Revoking a thread handle just clears the slot, doesn't affect the thread
            proc.removePerm(handle) catch {};
        },
        .empty => return E_BADCAP,
    }

    return E_OK;
}

const ReservationInfo = VirtualMemoryManager.ReservationInfo;
const PageRights = zag.memory.vmm.PageRights;

const ReservationCollection = struct {
    buf: [128]ReservationInfo = undefined,
    count: usize = 0,

    fn items(self: *const ReservationCollection) []const ReservationInfo {
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

fn sysDisableRestart() i64 {
    const proc = currentProc();
    if (proc.restart_context == null) return E_PERM;
    proc.disableRestart();
    return E_OK;
}

fn sysFutexWait(addr: u64, expected: u64, timeout_ns: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = currentProc();
    const vaddr = VAddr.fromInt(addr);
    const page_paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;
    const paddr = PAddr.fromInt(page_paddr.addr + (addr & 0xFFF));

    return futex.wait(paddr, expected, timeout_ns, sched.currentThread().?);
}

fn sysFutexWake(addr: u64, count: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = currentProc();
    const vaddr = VAddr.fromInt(addr);
    const page_paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;
    const paddr = PAddr.fromInt(page_paddr.addr + (addr & 0xFFF));

    return @intCast(futex.wake(paddr, @truncate(count)));
}

fn sysClockGettime() i64 {
    return @bitCast(arch.getMonotonicClock().now());
}

fn sysIoportRead(device_handle: u64, port_offset: u64, width: u64) i64 {
    if (width != 1 and width != 2 and width != 4) return E_INVAL;

    const proc = currentProc();
    const entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (entry.object != .device_region) return E_BADCAP;
    if (!entry.deviceRights().map) return E_PERM;

    const device = entry.object.device_region;
    if (device.device_type != .port_io) return E_INVAL;
    if (port_offset + width > device.access.port_io.port_count) return E_INVAL;

    const port: u16 = device.access.port_io.base_port + @as(u16, @truncate(port_offset));
    return @intCast(arch.ioportIn(port, @truncate(width)));
}

fn sysIoportWrite(device_handle: u64, port_offset: u64, width: u64, value: u64) i64 {
    if (width != 1 and width != 2 and width != 4) return E_INVAL;

    const proc = currentProc();
    const entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (entry.object != .device_region) return E_BADCAP;
    if (!entry.deviceRights().map) return E_PERM;

    const device = entry.object.device_region;
    if (device.device_type != .port_io) return E_INVAL;
    if (port_offset + width > device.access.port_io.port_count) return E_INVAL;

    const port: u16 = device.access.port_io.base_port + @as(u16, @truncate(port_offset));
    arch.ioportOut(port, @truncate(width), @truncate(value));
    return E_OK;
}

fn sysDmaMap(device_handle: u64, shm_handle: u64) i64 {
    const proc = currentProc();
    const dev_entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (dev_entry.object != .device_region) return E_BADCAP;
    if (!dev_entry.deviceRights().dma) return E_PERM;
    const device = dev_entry.object.device_region;
    if (device.device_type != .mmio) return E_INVAL;

    const shm_entry = proc.getPermByHandle(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;
    const shm = shm_entry.object.shared_memory;

    if (arch.isDmaRemapAvailable()) {
        const dma_base = arch.mapDmaPages(device, shm) catch return E_NOMEM;
        arch.enableDmaRemapping();
        proc.addDmaMapping(device, shm, dma_base, shm.pages.len) catch return E_NORES;
        return @bitCast(dma_base);
    } else return E_NOMEM;
}

fn sysPinExclusive(thread_handle: u64) i64 {
    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().pin_exclusive) return E_PERM;

    // Look up thread handle
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().set_affinity) return E_PERM;

    const thread = sched.currentThread().?;
    // Thread handle must refer to the calling thread
    if (thr_entry.object.thread != thread) return E_INVAL;

    const pin_result = sched.pinExclusive(thread);
    if (pin_result < 0) return pin_result;

    const core_id: u64 = @intCast(pin_result);
    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .core_pin = .{
            .core_id = core_id,
            .thread_tid = thread.tid,
        } },
        .rights = 0,
    };
    const handle_id = proc.insertPerm(entry) catch {
        _ = sched.unpinExclusive(thread);
        return E_MAXCAP;
    };

    return @intCast(handle_id);
}

// --- Thread Handle Syscalls ---

fn sysThreadSelf() i64 {
    const proc = currentProc();
    const thread = sched.currentThread().?;
    if (proc.findThreadHandle(thread)) |handle_id| {
        return @intCast(handle_id);
    }
    return E_INVAL;
}

fn sysThreadSuspend(thread_handle: u64) i64 {
    const proc = currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().@"suspend") return E_PERM;

    const target = thr_entry.object.thread;
    const target_proc = target.process;

    target_proc.lock.lock();
    defer target_proc.lock.unlock();

    switch (target.state) {
        .faulted => return E_BUSY,
        .suspended => return E_BUSY,
        .exited => return E_BADCAP,
        .running => {
            target.state = .suspended;
            target_proc.suspended_thread_slots |= @as(u64, 1) << @intCast(target.slot_index);
            // If running on another core, send IPI to force reschedule
            if (target.on_cpu.load(.acquire) and target != sched.currentThread().?) {
                if (target.core_affinity) |mask| {
                    arch.triggerSchedulerInterrupt(@intCast(@ctz(mask)));
                }
            }
        },
        .ready => {
            target.state = .suspended;
            target_proc.suspended_thread_slots |= @as(u64, 1) << @intCast(target.slot_index);
            // Note: ideally we'd remove from run queue, but the scheduler will
            // skip suspended threads when dequeuing
        },
        .blocked => {
            target.state = .suspended;
            target_proc.suspended_thread_slots |= @as(u64, 1) << @intCast(target.slot_index);
        },
    }
    target_proc.syncUserView();
    return E_OK;
}

fn sysThreadResume(thread_handle: u64) i64 {
    const proc = currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().@"resume") return E_PERM;

    const target = thr_entry.object.thread;
    const target_proc = target.process;

    target_proc.lock.lock();
    if (target.state != .suspended) {
        target_proc.lock.unlock();
        return E_INVAL;
    }

    target.state = .ready;
    target_proc.suspended_thread_slots &= ~(@as(u64, 1) << @intCast(target.slot_index));
    target_proc.syncUserView();
    target_proc.lock.unlock();

    const target_core = if (target.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
    sched.enqueueOnCore(target_core, target);
    return E_OK;
}

fn sysThreadKill(thread_handle: u64) i64 {
    const proc = currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().kill) return E_PERM;

    const target = thr_entry.object.thread;
    const target_proc = target.process;
    const cur = sched.currentThread().?;

    target_proc.lock.lock();
    if (target.state == .faulted) {
        target_proc.lock.unlock();
        return E_BUSY;
    }
    if (target.state == .exited) {
        target_proc.lock.unlock();
        return E_BADCAP;
    }

    const was_running = target.state == .running;
    const is_self = target == cur;
    target.state = .exited;
    // Clear bitmask bits
    target_proc.faulted_thread_slots &= ~(@as(u64, 1) << @intCast(target.slot_index));
    target_proc.suspended_thread_slots &= ~(@as(u64, 1) << @intCast(target.slot_index));
    target_proc.lock.unlock();

    // Self-kill: fall through to scheduler-zombie cleanup path.
    if (is_self) {
        arch.enableInterrupts();
        sched.yield();
        while (true) arch.halt();
    }

    // If running on another core, IPI it; scheduler picks it up as zombie.
    if (was_running) {
        if (target.core_affinity) |mask| {
            arch.triggerSchedulerInterrupt(@intCast(@ctz(mask)));
        }
        return E_OK;
    }

    // Off-CPU. If .ready, remove from run queue first to avoid dangling.
    sched.removeFromAnyRunQueue(target);
    if (target.futex_paddr.addr != 0) futex.removeBlockedThread(target);
    // deinit removes thread handles from perm tables, frees stacks,
    // calls lastThreadExited (which triggers process exit/restart).
    target.deinit();

    return E_OK;
}

fn sysFaultRecv(buf_ptr: u64, blocking: u64) i64 {
    const proc = currentProc();

    // Check that caller has fault_handler right
    var has_right = false;
    proc.perm_lock.lock();
    if (proc.perm_table[0].processRights().fault_handler) {
        has_right = true;
    } else {
        for (proc.perm_table[1..]) |slot| {
            if (slot.object == .process and slot.processHandleRights().fault_handler) {
                has_right = true;
                break;
            }
        }
    }
    proc.perm_lock.unlock();
    if (!has_right) return E_PERM;

    // Validate buffer address
    const FAULT_MSG_SIZE: u64 = 176; // matches libz FaultMessage layout
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const buf_end = std.math.add(u64, buf_ptr, FAULT_MSG_SIZE) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;
    var check_addr = buf_ptr;
    while (check_addr < buf_end) {
        const node = proc.vmm.findNode(VAddr.fromInt(check_addr)) orelse return E_BADADDR;
        if (!node.rights.write) return E_BADADDR;
        check_addr = node.end();
    }

    proc.lock.lock();

    if (proc.fault_pending and proc.fault_pending_delivered) {
        proc.lock.unlock();
        return E_BUSY;
    }

    // Non-blocking semantics for now: if blocking, spin-wait by yielding without
    // descheduling. This is suboptimal but avoids context-saving issues.
    if (!proc.fault_pending and blocking == 0) {
        proc.lock.unlock();
        return E_AGAIN;
    }

    // Blocking poll loop
    while (!proc.fault_pending) {
        proc.lock.unlock();
        arch.enableInterrupts();
        sched.yield();
        proc.lock.lock();
    }

    // Deliver the fault message
    const tid = proc.fault_pending_tid;
    const reason: u8 = proc.fault_pending_reason;
    const fault_addr: u64 = proc.fault_pending_addr;
    const process_handle: u64 = proc.fault_pending_proc_handle;
    const rip: u64 = proc.fault_pending_rip;
    proc.fault_pending_delivered = true;
    proc.lock.unlock();

    // Write FaultMessage to user buffer
    // Layout: process_handle(u64), thread_handle(u64), fault_reason(u8), _pad[7], fault_addr(u64), rip(u64), regs[136]
    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    @as(*align(1) u64, @ptrCast(buf + 0)).* = process_handle;
    @as(*align(1) u64, @ptrCast(buf + 8)).* = tid;
    buf[16] = reason;
    @memset(buf[17..24], 0);
    @as(*align(1) u64, @ptrCast(buf + 24)).* = fault_addr;
    @as(*align(1) u64, @ptrCast(buf + 32)).* = rip;
    @memset(buf[40..176], 0);

    return @intCast(tid);
}

fn sysFaultReply(fault_token: u64, action: u64, modified_regs_ptr: u64) i64 {
    const FAULT_KILL: u64 = 0;
    const FAULT_RESUME: u64 = 1;
    const FAULT_RESUME_MODIFIED: u64 = 2;
    if (action > FAULT_RESUME_MODIFIED) return E_INVAL;

    const proc = currentProc();

    // §4.34.6: validate modified_regs_ptr for RESUME_MODIFIED.
    if (action == FAULT_RESUME_MODIFIED) {
        if (!address.AddrSpacePartition.user.contains(modified_regs_ptr)) return E_BADADDR;
        const SAVED_REGS_SIZE: u64 = 144;
        const buf_end = std.math.add(u64, modified_regs_ptr, SAVED_REGS_SIZE) catch return E_BADADDR;
        if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;
        const node = proc.vmm.findNode(VAddr.fromInt(modified_regs_ptr)) orelse return E_BADADDR;
        if (!node.rights.read) return E_BADADDR;
    }

    proc.lock.lock();

    if (!proc.fault_pending or !proc.fault_pending_delivered) {
        proc.lock.unlock();
        return E_INVAL;
    }
    if (proc.fault_pending_tid != fault_token) {
        proc.lock.unlock();
        return E_NOENT;
    }

    const source = proc.fault_pending_source;

    // Clear pending state.
    proc.fault_pending = false;
    proc.fault_pending_tid = 0;
    proc.fault_pending_source = null;
    proc.fault_pending_thread = null;
    proc.fault_pending_delivered = false;
    proc.fault_pending_reason = 0;
    proc.fault_pending_addr = 0;
    proc.fault_pending_proc_handle = 0;
    proc.lock.unlock();

    if (source) |src| {
        switch (action) {
            FAULT_KILL => {
                src.kill(.killed);
            },
            FAULT_RESUME, FAULT_RESUME_MODIFIED => {
                // Find the .faulted thread and resume it; unsuspend siblings.
                src.lock.lock();
                var faulted_thread: ?*Thread = null;
                for (src.threads[0..src.num_threads]) |t| {
                    if (t.state == .faulted) {
                        faulted_thread = t;
                    } else if (t.state == .suspended) {
                        t.state = .ready;
                    }
                }
                src.suspended_thread_slots = 0;
                src.faulted_thread_slots = 0;
                if (faulted_thread) |ft| {
                    ft.state = .ready;
                }
                src.lock.unlock();
                // Re-enqueue all newly-ready threads.
                if (faulted_thread) |ft| {
                    const target_core = if (ft.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
                    sched.enqueueOnCore(target_core, ft);
                }
                src.lock.lock();
                for (src.threads[0..src.num_threads]) |t| {
                    if (t.state == .ready and t != faulted_thread) {
                        const target_core = if (t.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
                        src.lock.unlock();
                        sched.enqueueOnCore(target_core, t);
                        src.lock.lock();
                    }
                }
                src.lock.unlock();
            },
            else => unreachable,
        }
    }

    return E_OK;
}

fn sysFaultReadMem(proc_handle: u64, vaddr: u64, buf_ptr: u64, len: u64) i64 {
    const proc = currentProc();
    const entry = proc.getPermByHandle(proc_handle) orelse return E_BADCAP;
    if (entry.object != .process) return E_BADCAP;
    if (!entry.processHandleRights().fault_handler) return E_PERM;

    if (len == 0) return E_INVAL;

    const target = entry.object.process;

    // Validate caller's buffer is writable
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const buf_end = std.math.add(u64, buf_ptr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;

    // Read from target process's virtual address space via physmap
    var remaining = len;
    var src_addr = vaddr;
    var dst_addr = buf_ptr;
    while (remaining > 0) {
        const page_offset = src_addr & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_offset);
        const page_paddr = arch.resolveVaddr(target.addr_space_root, VAddr.fromInt(src_addr)) orelse return E_BADADDR;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_offset;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        const dst: [*]u8 = @ptrFromInt(dst_addr);
        @memcpy(dst[0..chunk], src[0..chunk]);
        remaining -= chunk;
        src_addr += chunk;
        dst_addr += chunk;
    }

    return E_OK;
}

fn sysFaultWriteMem(proc_handle: u64, vaddr: u64, buf_ptr: u64, len: u64) i64 {
    const proc = currentProc();
    const entry = proc.getPermByHandle(proc_handle) orelse return E_BADCAP;
    if (entry.object != .process) return E_BADCAP;
    if (!entry.processHandleRights().fault_handler) return E_PERM;

    if (len == 0) return E_INVAL;

    const target = entry.object.process;

    // Validate caller's buffer is readable
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const buf_end = std.math.add(u64, buf_ptr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;

    // Write to target process's virtual address space via physmap (bypasses page perms)
    var remaining = len;
    var dst_addr = vaddr;
    var src_addr = buf_ptr;
    while (remaining > 0) {
        const page_offset = dst_addr & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_offset);
        const page_paddr = arch.resolveVaddr(target.addr_space_root, VAddr.fromInt(dst_addr)) orelse return E_BADADDR;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_offset;
        const src: [*]const u8 = @ptrFromInt(src_addr);
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk], src[0..chunk]);
        remaining -= chunk;
        dst_addr += chunk;
        src_addr += chunk;
    }

    return E_OK;
}

fn sysFaultSetThreadMode(thread_handle: u64, mode: u64) i64 {
    if (mode > 2) return E_INVAL;

    const proc = currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;

    // Verify caller holds fault_handler for the thread's owning process
    const target_thread = thr_entry.object.thread;
    const target_proc = target_thread.process;
    if (target_proc.fault_handler_proc != proc) return E_PERM;

    // Update exclude flags on the thread's perm entry in caller's table
    proc.perm_lock.lock();
    defer proc.perm_lock.unlock();
    for (&proc.perm_table) |*slot| {
        if (slot.object == .thread and slot.object.thread == target_thread) {
            switch (mode) {
                0 => { // stop_all
                    slot.exclude_oneshot = false;
                    slot.exclude_permanent = false;
                },
                1 => { // exclude_next
                    slot.exclude_oneshot = true;
                    slot.exclude_permanent = false;
                },
                2 => { // exclude_permanent
                    slot.exclude_oneshot = false;
                    slot.exclude_permanent = true;
                },
                else => unreachable,
            }
            proc.syncUserView();
            return E_OK;
        }
    }
    return E_BADCAP;
}

// --- IPC Message Passing ---

fn copyPayload(dst: *ArchCpuContext, src: *const ArchCpuContext, word_count: u3) void {
    if (word_count >= 1) dst.regs.rdi = src.regs.rdi;
    if (word_count >= 2) dst.regs.rsi = src.regs.rsi;
    if (word_count >= 3) dst.regs.rdx = src.regs.rdx;
    if (word_count >= 4) dst.regs.r8 = src.regs.r8;
    if (word_count >= 5) dst.regs.r9 = src.regs.r9;
}

const IpcMetadata = struct {
    word_count: u3,
    cap_transfer: bool,
};

fn parseIpcMetadata(r14: u64) IpcMetadata {
    return .{
        .word_count = @truncate(r14 & 0x7),
        .cap_transfer = (r14 & 0x8) != 0,
    };
}

fn transferCapability(sender_proc: *Process, target_proc: *Process, handle_val: u64, rights_val: u64) i64 {
    sender_proc.perm_lock.lock();
    const src_entry = sender_proc.getPermByHandleLocked(handle_val) orelse {
        sender_proc.perm_lock.unlock();
        return E_BADCAP;
    };

    switch (src_entry.object) {
        .shared_memory => |shm| {
            if (!src_entry.shmRights().grant) {
                sender_proc.perm_lock.unlock();
                return E_PERM;
            }
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) {
                sender_proc.perm_lock.unlock();
                return E_PERM;
            }
            // Safe: perm_lock held, so revoke can't removePerm+decRef yet.
            shm.incRef();
            sender_proc.perm_lock.unlock();

            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .shared_memory = shm },
                .rights = granted_u16,
            };
            _ = target_proc.insertPerm(new_entry) catch {
                shm.decRef();
                return E_MAXCAP;
            };
            return E_OK;
        },
        .process => |proc_ptr| {
            sender_proc.perm_lock.unlock();
            if (handle_val == 0) {
                // Sending HANDLE_SELF: gives recipient a process handle to the sender.
                const granted_u16: u16 = @truncate(rights_val);
                const granted_phr: ProcessHandleRights = @bitCast(granted_u16);

                // If fault_handler bit is set, handle the fault_handler transfer
                if (granted_phr.fault_handler) {
                    // Clear fault_handler from sender's slot 0 ProcessRights
                    sender_proc.perm_lock.lock();
                    const self_rights = sender_proc.perm_table[0].processRights();
                    var new_rights = self_rights;
                    new_rights.fault_handler = false;
                    sender_proc.perm_table[0].rights = @bitCast(new_rights);
                    sender_proc.syncUserView();
                    sender_proc.perm_lock.unlock();

                    // Set fault_handler_proc on sender
                    sender_proc.fault_handler_proc = target_proc;

                    // Link sender into target's fault_handler_targets list
                    // so target's death can revert sender to self-handling.
                    target_proc.linkFaultHandlerTarget(sender_proc);

                    // Check if target already has a handle to sender, add fault_handler bit
                    target_proc.perm_lock.lock();
                    var found_existing = false;
                    for (&target_proc.perm_table) |*slot| {
                        if (slot.object == .process and slot.object.process == proc_ptr) {
                            var existing_rights: ProcessHandleRights = @bitCast(slot.rights);
                            existing_rights.fault_handler = true;
                            slot.rights = @bitCast(existing_rights);
                            found_existing = true;
                            break;
                        }
                    }
                    target_proc.perm_lock.unlock();

                    if (!found_existing) {
                        _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Add, 1, .acq_rel);
                        _ = target_proc.insertPerm(.{
                            .handle = 0,
                            .object = .{ .process = proc_ptr },
                            .rights = granted_u16,
                        }) catch {
                            _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Sub, 1, .acq_rel);
                            return E_MAXCAP;
                        };
                    }

                    // Insert thread handles for all current threads into handler's perm table.
                    // Note: We do NOT acquire sender_proc.lock here because sysIpcReply already
                    // holds it (this would be a self-deadlock). Thread create/destroy races are
                    // tolerable here — initial thread always exists.
                    const num_threads = sender_proc.num_threads;
                    var threads_copy: [Process.MAX_THREADS]*Thread = undefined;
                    @memcpy(threads_copy[0..num_threads], sender_proc.threads[0..num_threads]);

                    for (threads_copy[0..num_threads]) |t| {
                        _ = target_proc.insertThreadHandle(t, ThreadHandleRights.full) catch {};
                    }

                    target_proc.syncUserView();
                    return E_OK;
                }

                // Normal HANDLE_SELF transfer (no fault_handler)
                const new_entry = PermissionEntry{
                    .handle = 0,
                    .object = .{ .process = proc_ptr },
                    .rights = granted_u16,
                };
                _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Add, 1, .acq_rel);
                _ = target_proc.insertPerm(new_entry) catch {
                    _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Sub, 1, .acq_rel);
                    return E_MAXCAP;
                };
                return E_OK;
            }
            if (!src_entry.processHandleRights().grant) return E_PERM;
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) return E_PERM;
            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .process = proc_ptr },
                .rights = granted_u16,
            };
            _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Add, 1, .acq_rel);
            _ = target_proc.insertPerm(new_entry) catch {
                _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Sub, 1, .acq_rel);
                return E_MAXCAP;
            };
            return E_OK;
        },
        .device_region => |device| {
            sender_proc.perm_lock.unlock();
            if (!src_entry.deviceRights().grant) return E_PERM;
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) return E_PERM;
            // Device transfer is parent->child only
            if (target_proc.parent != sender_proc) return E_PERM;
            const target_self = target_proc.getPermByHandle(0) orelse return E_PERM;
            if (!target_self.processRights().device_own) return E_PERM;
            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .device_region = device },
                .rights = granted_u16,
            };
            _ = target_proc.insertPerm(new_entry) catch return E_MAXCAP;
            sender_proc.removePerm(handle_val) catch {};
            return E_OK;
        },
        .thread => {
            // Thread handles are not transferable via IPC
            sender_proc.perm_lock.unlock();
            return E_PERM;
        },
        else => {
            sender_proc.perm_lock.unlock();
            return E_INVAL;
        },
    }
}

/// Get payload registers for cap transfer (last 2 of N words)
fn getCapPayload(ctx: *const ArchCpuContext, word_count: u3) struct { handle: u64, rights: u64 } {
    const payload_regs = [5]u64{
        ctx.regs.rdi, ctx.regs.rsi, ctx.regs.rdx,
        ctx.regs.r8, ctx.regs.r9,
    };
    if (word_count < 2) return .{ .handle = 0, .rights = 0 };
    return .{
        .handle = payload_regs[word_count - 2],
        .rights = payload_regs[word_count - 1],
    };
}

fn validateIpcSendRights(entry: PermissionEntry, meta: IpcMetadata, sender_proc: *Process, src_ctx: *const ArchCpuContext) i64 {
    const rights = entry.processHandleRights();
    if (!rights.send_words) return E_PERM;
    if (meta.cap_transfer) {
        if (meta.word_count < 2) return E_INVAL;
        const cap = getCapPayload(src_ctx, meta.word_count);
        const cap_entry = sender_proc.getPermByHandle(cap.handle) orelse return E_BADCAP;
        switch (cap_entry.object) {
            .shared_memory => if (!rights.send_shm) return E_PERM,
            .process => if (!rights.send_process) return E_PERM,
            .device_region => if (!rights.send_device) return E_PERM,
            else => return E_INVAL,
        }
    }
    return E_OK;
}

fn wakeThread(thread: *Thread) void {
    while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
    sched.enqueueOnCore(target_core, thread);
}

fn sysIpcSend(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const target_handle = ctx.regs.r13;
    const meta = parseIpcMetadata(ctx.regs.r14);

    // Look up target process
    const target_entry = proc.getPermByHandle(target_handle) orelse return .{ .rax = E_BADCAP };
    if (target_entry.object != .process) return .{ .rax = E_BADCAP };
    const target_proc = target_entry.object.process;

    // §2.6.30: lazily convert dead process entries on IPC attempt.
    if (!target_proc.alive) {
        proc.convertToDeadProcess(target_proc);
        return .{ .rax = E_BADCAP };
    }

    // Validate rights
    const rights_check = validateIpcSendRights(target_entry, meta, proc, ctx);
    if (rights_check != E_OK) return .{ .rax = rights_check };

    target_proc.lock.lock();

    if (target_proc.receiver) |receiver| {
        // Receiver is waiting — deliver directly
        copyPayload(receiver.ctx, ctx, meta.word_count);
        // Set recv metadata: bit 0 = 0 (from send), bits [3:1] = word_count
        receiver.ctx.regs.r14 = @as(u64, meta.word_count) << 1;
        receiver.ctx.regs.rax = @bitCast(E_OK);

        // Handle capability transfer
        if (meta.cap_transfer) {
            const cap = getCapPayload(ctx, meta.word_count);
            const cap_result = transferCapability(proc, target_proc, cap.handle, cap.rights);
            if (cap_result != E_OK) {
                target_proc.lock.unlock();
                return .{ .rax = cap_result };
            }
        }

        target_proc.pending_reply = true;
        target_proc.pending_caller = null; // send has no caller to reply to
        const recv_thread = receiver;
        target_proc.receiver = null;
        target_proc.lock.unlock();

        wakeThread(recv_thread);
        return .{ .rax = E_OK };
    } else {
        // No receiver waiting
        target_proc.lock.unlock();
        return .{ .rax = E_AGAIN };
    }
}

fn sysIpcCall(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const target_handle = ctx.regs.r13;
    const meta = parseIpcMetadata(ctx.regs.r14);

    const target_entry = proc.getPermByHandle(target_handle) orelse return .{ .rax = E_BADCAP };
    if (target_entry.object != .process) return .{ .rax = E_BADCAP };
    const target_proc = target_entry.object.process;

    // §2.6.30: lazily convert dead process entries on IPC attempt.
    if (!target_proc.alive) {
        proc.convertToDeadProcess(target_proc);
        return .{ .rax = E_BADCAP };
    }

    const rights_check = validateIpcSendRights(target_entry, meta, proc, ctx);
    if (rights_check != E_OK) return .{ .rax = rights_check };

    target_proc.lock.lock();

    if (target_proc.receiver) |receiver| {
        // Receiver is waiting — deliver directly and switch
        copyPayload(receiver.ctx, ctx, meta.word_count);
        receiver.ctx.regs.r14 = (@as(u64, meta.word_count) << 1) | 1; // bit 0 = 1 (from call)
        receiver.ctx.regs.rax = @bitCast(E_OK);

        if (meta.cap_transfer) {
            const cap = getCapPayload(ctx, meta.word_count);
            const cap_result = transferCapability(proc, target_proc, cap.handle, cap.rights);
            if (cap_result != E_OK) {
                target_proc.lock.unlock();
                return .{ .rax = cap_result };
            }
        }

        target_proc.pending_reply = true;
        target_proc.pending_caller = thread;
        thread.ipc_server = target_proc;
        const recv_thread = receiver;
        target_proc.receiver = null;
        target_proc.lock.unlock();

        // Block caller and switch directly to receiver
        thread.state = .blocked;
        // switchToThread saves ctx and does the switch — never returns on success
        const result = sched.switchToThread(thread, recv_thread, ctx, false);
        // If we get here, switchToThread returned an error (E_BUSY)
        // Undo the IPC state
        target_proc.lock.lock();
        target_proc.pending_reply = false;
        target_proc.pending_caller = null;
        thread.ipc_server = null;
        thread.state = .running;
        // Re-block the receiver since we can't deliver
        target_proc.receiver = recv_thread;
        recv_thread.state = .blocked;
        target_proc.lock.unlock();
        return .{ .rax = result };
    } else {
        // No receiver — queue on wait list
        thread.next = null;
        if (target_proc.msg_waiters_tail) |tail| {
            tail.next = thread;
        } else {
            target_proc.msg_waiters_head = thread;
        }
        target_proc.msg_waiters_tail = thread;
        thread.ipc_server = target_proc;
        target_proc.lock.unlock();

        thread.state = .blocked;
        // switchToNextReady saves ctx and never returns
        thread.ctx = ctx;
        thread.on_cpu.store(false, .release);
        sched.switchToNextReady();
        // Never reached — when reply wakes us, we resume from ctx (int 0x80 frame)
        // with reply data already in registers
    }
}

fn sysIpcRecv(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const blocking = (ctx.regs.r14 & 0x2) != 0;

    // Must reply before receiving again
    if (proc.pending_reply) return .{ .rax = E_BUSY };

    proc.lock.lock();

    // Check if another thread is already receiving
    if (proc.receiver != null) {
        proc.lock.unlock();
        return .{ .rax = E_BUSY };
    }

    if (proc.msg_waiters_head) |waiter| {
        // Dequeue first waiter
        proc.msg_waiters_head = waiter.next;
        if (proc.msg_waiters_head == null) {
            proc.msg_waiters_tail = null;
        }
        waiter.next = null;

        // Copy payload from waiter's saved context
        const waiter_meta = parseIpcMetadata(waiter.ctx.regs.r14);
        copyPayload(ctx, waiter.ctx, waiter_meta.word_count);

        // Set recv metadata: bit 0 = 1 (always from call since send doesn't queue)
        ctx.regs.r14 = (@as(u64, waiter_meta.word_count) << 1) | 1;

        // Handle capability transfer
        if (waiter_meta.cap_transfer) {
            const cap = getCapPayload(waiter.ctx, waiter_meta.word_count);
            const cap_result = transferCapability(waiter.process, proc, cap.handle, cap.rights);
            if (cap_result != E_OK) {
                // Put waiter back at head (it was already dequeued)
                waiter.next = proc.msg_waiters_head;
                proc.msg_waiters_head = waiter;
                if (proc.msg_waiters_tail == null) {
                    proc.msg_waiters_tail = waiter;
                }
                proc.lock.unlock();
                return .{ .rax = cap_result };
            }
        }

        proc.pending_reply = true;
        proc.pending_caller = waiter;
        proc.lock.unlock();

        return .{ .rax = E_OK };
    } else if (blocking) {
        // Block on recv
        proc.receiver = thread;
        proc.lock.unlock();

        thread.state = .blocked;
        thread.ctx = ctx;
        thread.on_cpu.store(false, .release);
        sched.switchToNextReady();
        // Never reached — sender delivers message and wakes us via switchTo
    } else {
        proc.lock.unlock();
        return .{ .rax = E_AGAIN };
    }
}

fn sysIpcReply(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const r14 = ctx.regs.r14;
    const atomic_recv = (r14 & 0x1) != 0;
    const recv_blocking = (r14 & 0x2) != 0;
    const reply_word_count: u3 = @truncate((r14 >> 2) & 0x7);
    const reply_cap_transfer = (r14 & 0x20) != 0;

    proc.lock.lock();

    if (!proc.pending_reply) {
        proc.lock.unlock();
        return .{ .rax = E_INVAL };
    }

    var caller_thread: ?*Thread = null;

    if (proc.pending_caller) |pc| {
        // Reply to a call — copy reply payload to caller's saved context
        copyPayload(pc.ctx, ctx, reply_word_count);
        pc.ctx.regs.rax = @bitCast(E_OK);
        // Copy reply metadata to caller
        pc.ctx.regs.r14 = (@as(u64, reply_word_count) << 1) | 1;

        // Handle capability transfer on reply
        if (reply_cap_transfer) {
            const cap = getCapPayload(ctx, reply_word_count);
            _ = transferCapability(proc, pc.process, cap.handle, cap.rights);
        }

        pc.ipc_server = null;
        caller_thread = pc;
    }

    proc.pending_caller = null;
    proc.pending_reply = false;

    if (atomic_recv) {
        // Reply + recv atomically
        if (proc.msg_waiters_head) |waiter| {
            // There's a queued message — deliver it immediately
            proc.msg_waiters_head = waiter.next;
            if (proc.msg_waiters_head == null) {
                proc.msg_waiters_tail = null;
            }
            waiter.next = null;

            const waiter_meta = parseIpcMetadata(waiter.ctx.regs.r14);
            copyPayload(ctx, waiter.ctx, waiter_meta.word_count);
            ctx.regs.r14 = (@as(u64, waiter_meta.word_count) << 1) | 1;
            ctx.regs.rax = @bitCast(E_OK);

            if (waiter_meta.cap_transfer) {
                const cap = getCapPayload(waiter.ctx, waiter_meta.word_count);
                _ = transferCapability(waiter.process, proc, cap.handle, cap.rights);
            }

            proc.pending_reply = true;
            proc.pending_caller = waiter;
            proc.lock.unlock();

            // Wake the previous caller if any
            if (caller_thread) |ct| {
                wakeThread(ct);
            }

            return .{ .rax = E_OK };
        } else if (recv_blocking) {
            // No queued message — block on recv
            proc.receiver = thread;
            proc.lock.unlock();

            if (caller_thread) |ct| {
                // Switch directly to the caller we just replied to
                thread.state = .blocked;
                const result = sched.switchToThread(thread, ct, ctx, false);
                if (result != 0) {
                    // Undo
                    proc.lock.lock();
                    proc.receiver = null;
                    proc.lock.unlock();
                    thread.state = .running;
                    wakeThread(ct);
                    return .{ .rax = E_OK }; // Reply succeeded, only recv failed
                }
                unreachable;
            } else {
                thread.state = .blocked;
                thread.ctx = ctx;
                thread.on_cpu.store(false, .release);
                sched.switchToNextReady();
                unreachable;
            }
        } else {
            // Non-blocking recv, no message
            proc.lock.unlock();
            if (caller_thread) |ct| {
                wakeThread(ct);
            }
            ctx.regs.rax = @bitCast(E_AGAIN);
            return .{ .rax = E_AGAIN };
        }
    } else {
        // Plain reply (no atomic recv)
        proc.lock.unlock();

        if (caller_thread) |ct| {
            // Switch to caller, put self on run queue (enqueued inside switchToThread after ctx save)
            thread.state = .ready;
            ctx.regs.rax = @bitCast(E_OK);
            const result = sched.switchToThread(thread, ct, ctx, true);
            if (result != 0) {
                // switchToThread failed (E_BUSY), just wake caller normally
                thread.state = .running;
                wakeThread(ct);
                return .{ .rax = E_OK };
            }
            unreachable;
        } else {
            // Was a send, no one to switch to
            return .{ .rax = E_OK };
        }
    }
}

fn sysDmaUnmap(device_handle: u64, shm_handle: u64) i64 {
    const proc = currentProc();
    const dev_entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (dev_entry.object != .device_region) return E_BADCAP;
    const device = dev_entry.object.device_region;

    const shm_entry = proc.getPermByHandle(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;
    const shm = shm_entry.object.shared_memory;

    if (!arch.isDmaRemapAvailable()) {
        // No IOMMU: no page table entries to clean up, just remove tracking
        _ = proc.removeDmaMapping(device, shm);
        return E_OK;
    }

    const mapping = proc.removeDmaMapping(device, shm) orelse return E_NOENT;
    arch.unmapDmaPages(device, mapping.dma_base, mapping.num_pages);
    return E_OK;
}
