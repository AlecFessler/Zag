const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const address = zag.memory.address;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;

const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.sched.process.Process;
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

pub const SyscallResult = struct {
    rax: i64,
    rdx: u64 = 0,
};

pub const SyscallNum = enum(u64) {
    write,
    mem_reserve,
    mem_perms,
    proc_create,
    thread_create,
    thread_exit,
    thread_yield,
    thread_set_affinity,
    grant_perm,
    revoke_perm,
    futex_wait,
    futex_wake,
    clock_gettime,
    _,
};

fn currentProc() *Process {
    return sched.currentThread().?.proc;
}

fn isSubset(requested: u8, allowed: u8) bool {
    return (requested & ~allowed) == 0;
}

fn validateUserPtr(ptr: u64, len: u64) bool {
    if (len == 0) return true;
    const end = std.math.add(u64, ptr, len) catch return false;
    return ptr >= address.AddrSpacePartition.user.start and
        end <= address.AddrSpacePartition.user.end;
}

fn ok(val: i64) SyscallResult {
    return .{ .rax = val };
}

fn err(code: i64) SyscallResult {
    return .{ .rax = code };
}

pub fn dispatch(num: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) SyscallResult {
    const syscall_num: SyscallNum = @enumFromInt(num);
    return switch (syscall_num) {
        .write => ok(sysWrite(arg0, arg1)),
        .mem_reserve => sysMemReserve(arg0, arg1, arg2, arg3),
        .mem_perms => ok(sysMemPerms(arg0, arg1)),
        .proc_create => ok(sysProcCreate(arg0, arg1, arg2, arg3, arg4)),
        .thread_create => ok(sysThreadCreate(arg0, arg1, arg2)),
        .thread_exit => sysThreadExit(),
        .thread_yield => ok(sysThreadYield()),
        .thread_set_affinity => ok(sysThreadSetAffinity(arg0, arg1)),
        .grant_perm => ok(sysGrantPerm(arg0, arg1, arg2)),
        .revoke_perm => ok(sysRevokePerm(arg0)),
        .futex_wait => ok(sysFutexWait(arg0, arg1, arg2)),
        .futex_wake => ok(sysFutexWake(arg0, arg1)),
        .clock_gettime => ok(sysClockGettime()),
        _ => err(E_INVAL),
    };
}

fn sysWrite(buf_ptr: u64, buf_len: u64) i64 {
    if (!validateUserPtr(buf_ptr, buf_len)) return E_BADADDR;
    const buf: [*]const u8 = @ptrFromInt(buf_ptr);
    arch.print("{s}", .{buf[0..buf_len]});
    return E_OK;
}

// mem_reserve(hint, size, max_perms_bits, shared)
//   shared = 0: anonymous demand-paged VmReservation
//   shared = 1: eagerly-paged SharedMemory object
// Returns: rax = permission table handle (or error), rdx = vaddr (for anonymous)
fn sysMemReserve(hint: u64, size: u64, max_perms_bits: u64, shared_flag: u64) SyscallResult {
    _ = hint;
    if (size == 0 or !std.mem.isAligned(size, paging.PAGE4K)) return err(E_INVAL);
    const proc = currentProc();
    const self_entry = proc.getPerm(0) orelse return err(E_PERM);
    if (!self_entry.processRights().mem_reserve) return err(E_PERM);
    if (shared_flag == 1) {
        const shm = SharedMemory.create(size) catch return err(E_NOMEM);
        const shm_entry = PermissionEntry{
            .object = .{ .shared_memory = shm },
            .rights = @truncate(max_perms_bits),
        };
        const handle = proc.insertPerm(shm_entry) catch {
            shm.decRef();
            return err(E_MAXCAP);
        };
        return ok(@intCast(handle));
    } else {
        const requested_rights: VmReservationRights = @bitCast(@as(u8, @truncate(max_perms_bits)));
        const vaddr = proc.vmm.reserve(
            size,
            paging.pageAlign(.page4k),
            requested_rights,
        ) catch return err(E_NOMEM);
        const res = proc.vmm.findReservation(vaddr) orelse return err(E_NOMEM);
        const res_entry = PermissionEntry{
            .object = .{ .vm_reservation = res },
            .rights = @truncate(max_perms_bits),
        };
        const handle = proc.insertPerm(res_entry) catch return err(E_MAXCAP);
        return .{ .rax = @intCast(handle), .rdx = vaddr.addr };
    }
}

// mem_perms(handle, perms_bits)
// For vm_reservation: updates reservation rights and committed PTEs. perms=0 decommits.
// For shared_memory: maps shm pages into process address space with given perms.
//   Returns base vaddr on success for shm, E_OK for vm_reservation.
fn sysMemPerms(handle: u64, perms_bits: u64) i64 {
    const proc = currentProc();
    const handle_u32: u32 = @intCast(handle);
    const entry = proc.getPerm(handle_u32) orelse return E_BADCAP;

    const allowed: u8 = entry.rights;
    const requested: u8 = @truncate(perms_bits);

    if (requested != 0 and !isSubset(requested, allowed)) return E_PERM;

    switch (entry.object) {
        .vm_reservation => |res| {
            const new_rights: VmReservationRights = @bitCast(requested);
            res.rights = new_rights;
            // TODO: walk page tables for already-committed pages and update PTEs
            // TODO: if perms == 0, decommit pages and return physical memory to PMM
            return E_OK;
        },
        .shared_memory => |shm| {
            if (requested == 0) {
                // TODO: unmap existing shm mapping, release VA range
                return E_OK;
            }

            const rights: VmReservationRights = @bitCast(requested);
            const num_pages = shm.num_pages;
            const map_size = @as(u64, num_pages) * paging.PAGE4K;

            const vaddr = proc.vmm.reserveRange(map_size, paging.pageAlign(.page4k)) catch return E_NOMEM;

            const pmm_iface = pmm.global_pmm.?.allocator();
            var i: u32 = 0;
            while (i < num_pages) : (i += 1) {
                const page_vaddr = VAddr.fromInt(vaddr.addr + @as(u64, i) * paging.PAGE4K);
                const page_paddr = shm.pages[i];
                const perms = zag.perms.memory.MemoryPerms{
                    .write_perm = if (rights.write) .write else .no_write,
                    .execute_perm = if (rights.execute) .execute else .no_execute,
                    .cache_perm = .write_back,
                    .global_perm = .not_global,
                    .privilege_perm = .user,
                };
                arch.mapPage(
                    proc.addr_space_root,
                    page_paddr,
                    page_vaddr,
                    .page4k,
                    perms,
                    pmm_iface,
                ) catch return E_NOMEM;
            }

            // TODO: track this mapping (vaddr, size) so it can be unmapped on revoke or perms=0
            return @bitCast(vaddr.addr);
        },
        else => return E_INVAL,
    }
}

// TODO: needs ELF parser, new address space setup, capability table bootstrapping
// from caps array, initial thread creation
fn sysProcCreate(elf_ptr: u64, elf_len: u64, self_perms: u64, caps_ptr: u64, num_caps: u64) i64 {
    _ = elf_ptr;
    _ = elf_len;
    _ = self_perms;
    _ = caps_ptr;
    _ = num_caps;
    return E_INVAL;
}

fn sysThreadCreate(entry_addr: u64, stack_addr: u64, arg: u64) i64 {
    _ = arg; // TODO: pass arg in rdi of new thread's initial register state

    if (!validateUserPtr(entry_addr, 1)) return E_BADADDR;
    if (!validateUserPtr(stack_addr, 1)) return E_BADADDR;

    const proc = currentProc();
    const self_entry = proc.getPerm(0) orelse return E_PERM;
    if (!self_entry.processRights().spawn_thread) return E_PERM;

    const entry: *const fn () void = @ptrFromInt(entry_addr);
    const thread = Thread.createThread(proc, entry, null) catch return E_MAXTHREAD;
    sched.enqueueOnCore(arch.coreID(), thread);

    return @intCast(thread.tid);
}

fn sysThreadExit() noreturn {
    const thread = sched.currentThread().?;
    const proc = thread.proc;

    const last_in_proc = proc.removeThread(thread);
    thread.state = .exited;
    thread.last_in_proc = last_in_proc;

    sched.yield();
    unreachable;
}

fn sysThreadYield() i64 {
    sched.yield();
    return E_OK;
}

fn sysThreadSetAffinity(tid: u64, core_mask: u64) i64 {
    _ = core_mask;

    const proc = currentProc();
    const self_entry = proc.getPerm(0) orelse return E_PERM;
    if (!self_entry.processRights().set_affinity) return E_PERM;

    proc.lock.lock();
    defer proc.lock.unlock();

    for (proc.threads[0..proc.num_threads]) |thread| {
        if (thread.tid == tid or tid == 0) {
            // TODO: update thread.core_affinity and migrate if currently on wrong core
            return E_OK;
        }
    }

    return E_NOENT;
}

fn sysGrantPerm(handle: u64, target_handle: u64, perms: u64) i64 {
    const proc = currentProc();
    const handle_u32: u32 = @intCast(handle);
    const target_u32: u32 = @intCast(target_handle);
    const perms_u8: u8 = @truncate(perms);

    const src_entry = proc.getPerm(handle_u32) orelse return E_BADCAP;

    if (src_entry.object != .shared_memory) return E_INVAL;
    if (!src_entry.shmRights().grant) return E_PERM;
    if (!isSubset(perms_u8, src_entry.rights)) return E_PERM;

    const target_entry = proc.getPerm(target_u32) orelse return E_BADCAP;
    if (target_entry.object != .process) return E_INVAL;
    if (!target_entry.processRights().grant_to) return E_PERM;

    const target_proc = target_entry.object.process;
    const shm = src_entry.object.shared_memory;

    const new_entry = PermissionEntry{
        .object = .{ .shared_memory = shm },
        .rights = perms_u8,
    };

    shm.incRef();
    const idx = target_proc.insertPerm(new_entry) catch {
        shm.decRef();
        return E_MAXCAP;
    };

    return @intCast(idx);
}

fn sysRevokePerm(handle: u64) i64 {
    const proc = currentProc();
    const handle_u32: u32 = @intCast(handle);

    const entry = proc.getPerm(handle_u32) orelse return E_BADCAP;

    switch (entry.object) {
        .shared_memory => |shm| {
            // TODO: unmap any active mapping of this shm in this process
            shm.decRef();
        },
        .vm_reservation => {
            // TODO: unmap committed pages, free physical memory, release VA range
        },
        .process => {},
        .empty => return E_BADCAP,
    }

    proc.removePerm(handle_u32) catch return E_INVAL;
    return E_OK;
}

// TODO: needs global futex wait queue keyed by physical address,
// atomic compare-and-block, timeout support
fn sysFutexWait(addr: u64, expected: u64, timeout_ns: u64) i64 {
    _ = addr;
    _ = expected;
    _ = timeout_ns;
    return E_INVAL;
}

// TODO: needs global futex wait queue keyed by physical address
fn sysFutexWake(addr: u64, count: u64) i64 {
    _ = addr;
    _ = count;
    return E_INVAL;
}

// TODO: needs calibrated TSC or architectural timer read
fn sysClockGettime() i64 {
    return 0;
}
