const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const errors = zag.syscall.errors;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const process_mod = zag.proc.process;
const sched = zag.sched.scheduler;

const isSubset = zag.perms.permissions.isSubset;

const PermissionEntry = zag.perms.permissions.PermissionEntry;
const SharedMemory = zag.memory.shared.SharedMemory;
const VAddr = zag.memory.address.VAddr;
const VmReservationRights = zag.perms.permissions.VmReservationRights;

const E_BADCAP = errors.E_BADCAP;
const E_EXIST = errors.E_EXIST;
const E_INVAL = errors.E_INVAL;
const E_MAXCAP = errors.E_MAXCAP;
const E_NOENT = errors.E_NOENT;
const E_NOMEM = errors.E_NOMEM;
const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

const SyscallResult = zag.syscall.dispatch.SyscallResult;

pub fn sysMemReserve(hint: u64, size: u64, max_perms_bits: u64) SyscallResult {
    kprof.enter(.sys_mem_reserve);
    defer kprof.exit(.sys_mem_reserve);
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return .{ .ret = E_INVAL };

    // Bound hint + size up front so `VirtualMemoryManager.reserve` can
    // never see an overflowing pair. The sibling VM syscalls in this
    // file (sysMemPerms, sysMemShmMap, sysMemUnmap) use the same idiom.
    // hint == 0 means "no hint — pick any free range", and is handled
    // by vmm.reserve's hint-path guard (`hint.addr != 0`) below, so we
    // only partition-check when the caller actually supplied one.
    if (hint != 0) {
        const end = std.math.add(u64, hint, size) catch return .{ .ret = E_INVAL };
        if (!address.AddrSpacePartition.user.contains(hint)) return .{ .ret = E_INVAL };
        if (!address.AddrSpacePartition.user.contains(end -| 1)) return .{ .ret = E_INVAL };
    }

    const max_rights: VmReservationRights = @bitCast(@as(u8, @truncate(max_perms_bits)));
    if (max_rights.shareable and max_rights.mmio) return .{ .ret = E_INVAL };
    if (max_rights.write_combining and !max_rights.mmio) return .{ .ret = E_INVAL };

    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return .{ .ret = E_PERM };
    if (!self_entry.processRights().mem_reserve) return .{ .ret = E_PERM };

    const result = proc.vmm.reserve(VAddr.fromInt(hint), size, max_rights) catch return .{ .ret = E_NOMEM };

    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .vm_reservation = .{
            .max_rights = max_rights,
            .original_start = result.vaddr,
            .original_size = size,
        } },
        .rights = @truncate(max_perms_bits),
    };
    const handle_id = proc.insertPerm(entry) catch return .{ .ret = E_MAXCAP };
    result.node.handle = handle_id;

    return .{ .ret = @intCast(handle_id), .ret2 = result.vaddr.addr };
}

pub fn sysMemPerms(vm_handle: u64, offset: u64, size: u64, perms_bits: u64) i64 {
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return E_INVAL;

    const new_rights: VmReservationRights = @bitCast(@as(u8, @truncate(perms_bits)));
    if (new_rights.shareable or new_rights.mmio or new_rights.write_combining) return E_INVAL;

    const proc = sched.currentProc();
    const entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = entry.object.vm_reservation;

    const new_rwx = @as(u16, @truncate(perms_bits)) & 0b111;
    if (new_rwx == 0) return E_INVAL;

    const max_rwx =
        @as(u16, @intFromBool(vm_res.max_rights.read)) |
        (@as(u16, @intFromBool(vm_res.max_rights.write)) << 1) |
        (@as(u16, @intFromBool(vm_res.max_rights.execute)) << 2);
    if (!isSubset(new_rwx, max_rwx)) return E_PERM;

    const range_end = std.math.add(u64, offset, size) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.memPerms(
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        size,
        new_rights,
    ) catch return E_INVAL;

    return E_OK;
}

pub fn sysMemShmCreate(size: u64, rights_bits: u64) i64 {
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) {
        return E_INVAL;
    }
    if (rights_bits == 0) return E_INVAL;

    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse {
        return E_PERM;
    };
    if (!self_entry.processRights().mem_shm_create) {
        return E_PERM;
    }

    const shm = SharedMemory.create(size) catch {
        return E_NOMEM;
    };

    const rights: u16 = @truncate(rights_bits);
    const entry = PermissionEntry{
        .handle = 0,
        .object = .{ .shared_memory = process_mod.slabRefNow(SharedMemory, shm) },
        .rights = rights,
    };
    const handle_id = proc.insertPerm(entry) catch {
        shm.decRef();
        return E_MAXCAP;
    };

    return @intCast(handle_id);
}

pub fn sysMemShmMap(shm_handle: u64, vm_handle: u64, offset: u64) i64 {
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;

    const proc = sched.currentProc();

    // Hold perm_lock across both lookups and the vmm.mem_shm_map call to
    // prevent a concurrent revoke_perm from freeing the SharedMemory
    // while we are using its pointer.  Without this, there is a UAF:
    // the revoke frees the SHM between getPermByHandle and vmm.mem_shm_map.
    //
    // Lock ordering: perm_lock -> vmm.lock is safe because no code path
    // acquires vmm.lock before perm_lock.
    proc.perm_lock.lock();
    defer proc.perm_lock.unlock();

    const shm_entry = proc.getPermByHandleLocked(shm_handle) orelse return E_BADCAP;
    if (shm_entry.object != .shared_memory) return E_BADCAP;

    const vm_entry = proc.getPermByHandleLocked(vm_handle) orelse return E_BADCAP;
    if (vm_entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = vm_entry.object.vm_reservation;
    if (!vm_res.max_rights.shareable) return E_PERM;

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

    const shm = shm_entry.object.shared_memory.lock() catch return E_BADCAP;
    defer shm_entry.object.shared_memory.unlock();

    const range_end = std.math.add(u64, offset, shm.size()) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.memShmMap(
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

pub fn sysMemUnmap(vm_handle: u64, offset: u64, size: u64) i64 {
    kprof.enter(.sys_mem_unmap);
    defer kprof.exit(.sys_mem_unmap);
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return E_INVAL;

    const proc = sched.currentProc();
    const entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = entry.object.vm_reservation;

    const range_end = std.math.add(u64, offset, size) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.memUnmap(
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        size,
        vm_res.max_rights,
    ) catch return E_INVAL;

    return E_OK;
}
