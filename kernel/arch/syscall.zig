const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const futex = zag.sched.futex;
const iommu = zag.arch.x64.iommu;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;

const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.sched.process.Process;
const ProcessRights = zag.perms.permissions.ProcessRights;
const SharedMemory = zag.memory.shared.SharedMemory;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
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
    grant_perm,
    revoke_perm,
    disable_restart,
    futex_wait,
    futex_wake,
    clock_gettime,
    shutdown,
    ioport_read,
    ioport_write,
    dma_map,
    dma_unmap,
    pci_enable_bus_master,
    _,
};

fn currentProc() *Process {
    return sched.currentThread().?.process;
}

fn isSubset(requested: u16, allowed: u16) bool {
    return (requested & ~allowed) == 0;
}

fn ok(val: i64) SyscallResult {
    return .{ .rax = val };
}

fn err(code: i64) SyscallResult {
    return .{ .rax = code };
}

var dbg_dispatch_count: u32 = 0;
pub fn dispatch(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) SyscallResult {
    _ = arg4;
    dbg_dispatch_count += 1;
    if (dbg_dispatch_count <= 30) {
        arch.print("K: syscall {d}\n", .{num});
    }
    const syscall_num: SyscallNum = @enumFromInt(num);
    return switch (syscall_num) {
        .write => sysWrite(arg0, arg1),
        .vm_reserve => sysVmReserve(arg0, arg1, arg2),
        .vm_perms => ok(sysVmPerms(arg0, arg1, arg2, arg3)),
        .shm_create => ok(sysShmCreate(arg0, arg1)),
        .shm_map => ok(sysShmMap(arg0, arg1, arg2)),
        .shm_unmap => ok(sysShmUnmap(arg0, arg1)),
        .mmio_map => ok(sysMmioMap(arg0, arg1, arg2)),
        .mmio_unmap => ok(sysMmioUnmap(arg0, arg1)),
        .proc_create => ok(sysProcCreate(arg0, arg1, arg2)),
        .thread_create => ok(sysThreadCreate(arg0, arg1, arg2)),
        .thread_exit => sysThreadExit(),
        .thread_yield => ok(sysThreadYield()),
        .set_affinity => ok(sysSetAffinity(arg0)),
        .grant_perm => ok(sysGrantPerm(arg0, arg1, arg2)),
        .revoke_perm => ok(sysRevokePerm(arg0)),
        .disable_restart => ok(sysDisableRestart()),
        .futex_wait => ok(sysFutexWait(arg0, arg1, arg2)),
        .futex_wake => ok(sysFutexWake(arg0, arg1)),
        .clock_gettime => ok(sysClockGettime()),
        .shutdown => sysShutdown(),
        .ioport_read => ok(sysIoportRead(arg0, arg1, arg2)),
        .ioport_write => ok(sysIoportWrite(arg0, arg1, arg2, arg3)),
        .dma_map => ok(sysDmaMap(arg0, arg1)),
        .dma_unmap => ok(sysDmaUnmap(arg0, arg1)),
        .pci_enable_bus_master => ok(sysPciEnableBusMaster(arg0)),
        _ => err(E_INVAL),
    };
}

var dbg_write_count: u32 = 0;
fn sysWrite(ptr: u64, len: u64) SyscallResult {
    if (len == 0) return ok(0);
    if (len > 4096) return err(E_INVAL);
    dbg_write_count += 1;
    if (dbg_write_count <= 5) {
        const proc = currentProc();
        arch.print("K: write pid={d} len={d} ptr=0x{x}\n", .{ proc.pid, len, ptr });
    }
    if (!address.AddrSpacePartition.user.contains(ptr)) return err(E_BADADDR);
    const end = std.math.add(u64, ptr, len) catch return err(E_BADADDR);
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return err(E_BADADDR);
    const msg: []const u8 = @as([*]const u8, @ptrFromInt(ptr))[0..len];
    arch.print("{s}", .{msg});
    return ok(@intCast(len));
}

fn sysVmReserve(hint: u64, size: u64, max_perms_bits: u64) SyscallResult {
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return err(E_INVAL);

    const max_rights: VmReservationRights = @bitCast(@as(u8, @truncate(max_perms_bits)));
    if (max_rights.shareable and max_rights.mmio) return err(E_INVAL);

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return err(E_PERM);
    if (!self_entry.processRights().mem_reserve) return err(E_PERM);

    const result = proc.vmm.reserve(VAddr.fromInt(hint), size, max_rights) catch return err(E_NOMEM);

    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .vm_reservation = .{
            .max_rights = max_rights,
            .original_start = result.vaddr,
            .original_size = size,
        } },
        .rights = @truncate(max_perms_bits),
    };
    const handle_id = proc.insertPerm(entry) catch return err(E_MAXCAP);
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

var dbg_shm_count: u32 = 0;
fn sysShmCreate(size: u64, rights_bits: u64) i64 {
    dbg_shm_count += 1;
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) {
        if (dbg_shm_count <= 5) arch.print("K: shm_create INVAL s={d} r={d}\n", .{ size, rights_bits });
        return E_INVAL;
    }

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse {
        if (dbg_shm_count <= 5) arch.print("K: shm_create NOPERM pid={d}\n", .{proc.pid});
        return E_PERM;
    };
    if (!self_entry.processRights().shm_create) {
        if (dbg_shm_count <= 5) arch.print("K: shm_create NOSHM pid={d}\n", .{proc.pid});
        return E_PERM;
    }

    const shm = SharedMemory.create(size) catch {
        if (dbg_shm_count <= 5) arch.print("K: shm_create NOMEM pid={d} s={d}\n", .{ proc.pid, size });
        return E_NOMEM;
    };

    const rights: u16 = if (rights_bits == 0) 0b1111 else @truncate(rights_bits);
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

    const shm_entry = proc.getPermByHandle(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;

    const vm_entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
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
        error.CommittedPages => E_BUSY,
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

    const range_end = std.math.add(u64, offset, device.size) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.mmio_map(
        device_handle,
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        device,
    ) catch |e| return switch (e) {
        error.CommittedPages => E_BUSY,
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

fn sysProcCreate(elf_ptr: u64, elf_len: u64, perms: u64) i64 {
    if (elf_len == 0) return E_INVAL;
    if (!address.AddrSpacePartition.user.contains(elf_ptr)) return E_BADADDR;
    const elf_end = std.math.add(u64, elf_ptr, elf_len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(elf_end -| 1)) return E_BADADDR;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().spawn_process) return E_PERM;

    const child_perms: ProcessRights = @bitCast(@as(u16, @truncate(perms)));
    if (child_perms.restart and proc.restart_context == null) return E_PERM;

    const elf_bytes: [*]const u8 = @ptrFromInt(elf_ptr);
    const elf_binary = elf_bytes[0..elf_len];

    const child = Process.create(elf_binary, child_perms, proc) catch |e| return switch (e) {
        error.InvalidElf => E_INVAL,
        else => E_NOMEM,
    };

    const child_entry = PermissionEntry{
        .handle = 0,
        .object = .{ .process = child },
        .rights = @truncate(perms),
    };
    const handle_id = proc.insertPerm(child_entry) catch {
        child.kill();
        return E_MAXCAP;
    };

    arch.print("K: proc_create pid={d} entry=0x{x}\n", .{ child.pid, child.threads[0].ctx.*.rip });
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
        else => E_NOMEM,
    };
    sched.enqueueOnCore(arch.coreID(), thread);

    return E_OK;
}

fn sysThreadExit() noreturn {
    const thread = sched.currentThread().?;
    const is_last = thread.process.removeThread(thread);
    thread.last_in_proc = is_last;
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

fn sysSetAffinity(core_mask: u64) i64 {
    if (core_mask == 0) return E_INVAL;
    const count = arch.coreCount();
    const valid_mask: u64 = if (count >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(count)) - 1;
    if (core_mask & ~valid_mask != 0) return E_INVAL;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().set_affinity) return E_PERM;

    sched.currentThread().?.core_affinity = core_mask;
    return E_OK;
}

fn sysGrantPerm(src_handle: u64, target_proc_handle: u64, granted_rights: u64) i64 {
    const proc = currentProc();
    const granted_u16: u16 = @truncate(granted_rights);

    const src_entry = proc.getPermByHandle(src_handle) orelse return E_BADCAP;

    const target_entry = proc.getPermByHandle(target_proc_handle) orelse return E_BADCAP;
    if (target_entry.object != .process) return E_BADCAP;
    if (!target_entry.processRights().grant_to) return E_PERM;

    const target_proc = target_entry.object.process;

    switch (src_entry.object) {
        .shared_memory => |shm| {
            if (!src_entry.shmRights().grant) return E_PERM;
            if (!isSubset(granted_u16, src_entry.rights)) return E_PERM;

            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .shared_memory = shm },
                .rights = granted_u16,
            };
            shm.incRef();
            _ = target_proc.insertPerm(new_entry) catch {
                shm.decRef();
                return E_MAXCAP;
            };
            return E_OK;
        },
        .device_region => |device| {
            if (!src_entry.deviceRights().grant) return E_PERM;
            if (!isSubset(granted_u16, src_entry.rights)) return E_PERM;
            const target_self = target_proc.getPermByHandle(0) orelse return E_PERM;
            if (!target_self.processRights().device_own) return E_PERM;

            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .device_region = device },
                .rights = granted_u16,
            };
            _ = target_proc.insertPerm(new_entry) catch return E_MAXCAP;
            proc.removePerm(src_handle) catch {};
            return E_OK;
        },
        else => return E_INVAL,
    }
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
            proc.vmm.revokeShmHandle(shm);
            shm.decRef();
            proc.removePerm(handle) catch {};
        },
        .device_region => |device| {
            proc.vmm.revokeMmioHandle(device);
            Process.returnDeviceHandleUpTree(proc, entry.rights, device);
            proc.removePerm(handle) catch {};
        },
        .process => |child| {
            child.killSubtree();
            proc.removePerm(handle) catch {};
        },
        .empty => return E_BADCAP,
    }

    return E_OK;
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
    const paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;

    return futex.wait(paddr, expected, timeout_ns, sched.currentThread().?);
}

fn sysFutexWake(addr: u64, count: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = currentProc();
    const vaddr = VAddr.fromInt(addr);
    const paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;

    return @intCast(futex.wake(paddr, @truncate(count)));
}

fn sysClockGettime() i64 {
    return @bitCast(arch.getMonotonicClock().now());
}

fn sysShutdown() noreturn {
    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0);
    if (self_entry) |entry| {
        if (entry.processRights().shutdown) {
            arch.print("shutdown: initiated by process\n", .{});
            arch.shutdown();
        }
    }
    arch.print("shutdown: denied (no permission)\n", .{});
    while (true) {
        arch.enableInterrupts();
        asm volatile ("hlt");
    }
}

fn sysIoportRead(device_handle: u64, port_offset: u64, width: u64) i64 {
    if (width != 1 and width != 2 and width != 4) return E_INVAL;

    const proc = currentProc();
    const entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (entry.object != .device_region) return E_BADCAP;
    if (!entry.deviceRights().map) return E_PERM;

    const device = entry.object.device_region;
    if (device.device_type != .port_io) return E_INVAL;
    if (port_offset + width > device.port_count) return E_INVAL;

    const port: u16 = device.base_port + @as(u16, @truncate(port_offset));
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
    if (port_offset + width > device.port_count) return E_INVAL;

    const port: u16 = device.base_port + @as(u16, @truncate(port_offset));
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

    if (iommu.isAvailable()) {
        const dma_base = iommu.mapDmaPages(device, shm) catch return E_NOMEM;
        iommu.enableTranslation();
        proc.addDmaMapping(device, shm, dma_base, shm.pages.len) catch return E_NOMEM;
        return @bitCast(dma_base);
    }

    // No IOMMU fallback: requires contiguous physical pages
    if (shm.pages.len == 0) return E_INVAL;
    const base = shm.pages[0].addr;
    for (shm.pages[1..], 1..) |p, i| {
        if (p.addr != base + @as(u64, i) * paging.PAGE4K) return E_NOMEM;
    }
    return @bitCast(base);
}

fn sysPciEnableBusMaster(device_handle: u64) i64 {
    const proc = currentProc();
    const entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (entry.object != .device_region) return E_BADCAP;
    if (!entry.deviceRights().dma) return E_PERM;
    const device = entry.object.device_region;

    pciEnableBusMaster(device.pci_bus, device.pci_dev, device.pci_func);
    return 0;
}

fn pciEnableBusMaster(bus: u8, dev: u8, func: u8) void {
    const cpu = @import("x64/cpu.zig");
    const addr: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, dev) << 11) |
        (@as(u32, func) << 8) |
        0x04;
    cpu.outd(addr, 0xCF8);
    const cmd = cpu.ind(0xCFC);
    cpu.outd(cmd | 0x06, 0xCFC);
}

fn sysDmaUnmap(device_handle: u64, shm_handle: u64) i64 {
    const proc = currentProc();
    const dev_entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (dev_entry.object != .device_region) return E_BADCAP;
    const device = dev_entry.object.device_region;

    const shm_entry = proc.getPermByHandle(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;
    const shm = shm_entry.object.shared_memory;

    if (!iommu.isAvailable()) {
        // No IOMMU: no page table entries to clean up, just remove tracking
        _ = proc.removeDmaMapping(device, shm);
        return E_OK;
    }

    const mapping = proc.removeDmaMapping(device, shm) orelse return E_NOENT;
    iommu.unmapDmaPages(device, mapping.dma_base, mapping.num_pages);
    return E_OK;
}
