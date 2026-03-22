const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const futex = zag.sched.futex;
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
    _,
};

fn currentProc() *Process {
    return sched.currentThread().?.process;
}

fn isSubset(requested: u8, allowed: u8) bool {
    return (requested & ~allowed) == 0;
}

fn ok(val: i64) SyscallResult {
    return .{ .rax = val };
}

fn err(code: i64) SyscallResult {
    return .{ .rax = code };
}

pub fn dispatch(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) SyscallResult {
    _ = arg4;
    const syscall_num: SyscallNum = @enumFromInt(num);
    return switch (syscall_num) {
        .write => sysWrite(arg0, arg1),
        .vm_reserve => sysVmReserve(arg0, arg1, arg2),
        .vm_perms => ok(sysVmPerms(arg0, arg1, arg2, arg3)),
        .shm_create => ok(sysShmCreate(arg0)),
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
        .futex_wait => ok(sysFutexWait(arg0, arg1)),
        .futex_wake => ok(sysFutexWake(arg0, arg1)),
        .clock_gettime => ok(sysClockGettime()),
        _ => err(E_INVAL),
    };
}

fn sysWrite(ptr: u64, len: u64) SyscallResult {
    if (len == 0) return ok(0);
    if (len > 4096) return err(E_INVAL);
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

    const new_rwx = @as(u8, @truncate(perms_bits)) & 0b111;
    const max_rwx =
        @as(u8, @intFromBool(vm_res.max_rights.read)) |
        (@as(u8, @intFromBool(vm_res.max_rights.write)) << 1) |
        (@as(u8, @intFromBool(vm_res.max_rights.execute)) << 2);
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

fn sysShmCreate(size: u64) i64 {
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return E_INVAL;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().shm_create) return E_PERM;

    const shm = SharedMemory.create(size) catch return E_NOMEM;

    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .shared_memory = shm },
        .rights = 0b1111,
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
    const max_rwx =
        @as(u8, @intFromBool(vm_res.max_rights.read)) |
        (@as(u8, @intFromBool(vm_res.max_rights.write)) << 1) |
        (@as(u8, @intFromBool(vm_res.max_rights.execute)) << 2);
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

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().spawn_process) return E_PERM;

    const child_perms: ProcessRights = @bitCast(@as(u8, @truncate(perms)));
    if (child_perms.restart and !self_entry.processRights().restart) return E_PERM;

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
    sched.yield();
    while (true) {
        arch.enableInterrupts();
        asm volatile ("hlt");
    }
}

fn sysThreadYield() i64 {
    sched.yield();
    return E_OK;
}

fn sysSetAffinity(core_mask: u64) i64 {
    if (core_mask == 0) return E_INVAL;
    const count = arch.coreCount();
    if (count < 64 and core_mask >= (@as(u64, 1) << @intCast(count))) return E_INVAL;

    const proc = currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().set_affinity) return E_PERM;

    sched.currentThread().?.core_affinity = core_mask;
    return E_OK;
}

fn sysGrantPerm(src_handle: u64, target_proc_handle: u64, granted_rights: u64) i64 {
    const proc = currentProc();
    const granted_u8: u8 = @truncate(granted_rights);

    const src_entry = proc.getPermByHandle(src_handle) orelse return E_BADCAP;

    const target_entry = proc.getPermByHandle(target_proc_handle) orelse return E_BADCAP;
    if (target_entry.object != .process) return E_BADCAP;
    if (!target_entry.processRights().grant_to) return E_PERM;

    const target_proc = target_entry.object.process;

    switch (src_entry.object) {
        .shared_memory => |shm| {
            if (!src_entry.shmRights().grant) return E_PERM;
            if (!isSubset(granted_u8, src_entry.rights)) return E_PERM;

            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .shared_memory = shm },
                .rights = granted_u8,
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
            if (!isSubset(granted_u8, src_entry.rights)) return E_PERM;
            const target_self = target_proc.getPermByHandle(0) orelse return E_PERM;
            if (!target_self.processRights().device_own) return E_PERM;

            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .device_region = device },
                .rights = granted_u8,
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

fn sysFutexWait(addr: u64, expected: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = currentProc();
    const vaddr = VAddr.fromInt(addr);
    const paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;

    return futex.wait(paddr, expected, sched.currentThread().?);
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

