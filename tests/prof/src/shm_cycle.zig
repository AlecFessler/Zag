const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

const PAGE_SIZE: u64 = 4096;
const SHM_PAGES: u64 = 16;
const SHM_SIZE: u64 = SHM_PAGES * PAGE_SIZE;

/// kprof workload — drives sys_mem_shm_create / sys_mem_shm_map /
/// sys_mem_reserve / sys_mem_unmap / sys_revoke_perm end-to-end across
/// two processes. Each iteration: parent creates an SHM, hands it to
/// the child via ipc_call_cap, child reserves+maps+touches+unmaps+
/// revokes its half and replies, then parent does its own reserve+
/// map+touch+unmap+revoke and finally revokes the SHM itself. Exercises
/// the full SHM lifecycle (plus the VMM reservation insert/remove path)
/// and the slab/heap allocators that back them.
pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
    }).bits();
    const ch_rc: i64 = syscall.proc_create(
        @intFromPtr(children.child_shm_cycle.ptr),
        children.child_shm_cycle.len,
        child_rights,
    );
    if (ch_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const child_handle: u64 = @bitCast(ch_rc);

    const shm_rights = perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    };
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();

    var iter: u64 = 0;
    while (iter < 50) : (iter += 1) {
        const shm_rc = syscall.shm_create_with_rights(SHM_SIZE, shm_rights.bits());
        if (shm_rc < 0) {
            syscall.thread_yield();
            continue;
        }
        const shm_handle: u64 = @bitCast(shm_rc);

        var reply: syscall.IpcMessage = .{};
        if (syscall.ipc_call_cap(
            child_handle,
            &.{ shm_handle, shm_rights.bits() },
            &reply,
        ) != 0) {
            _ = syscall.revoke_perm(shm_handle);
            syscall.thread_yield();
            continue;
        }

        const vm = syscall.mem_reserve(0, SHM_SIZE, vm_rights);
        if (vm.val < 0) {
            _ = syscall.revoke_perm(shm_handle);
            continue;
        }
        const vm_handle: u64 = @bitCast(vm.val);

        if (syscall.mem_shm_map(shm_handle, vm_handle, 0) != 0) {
            _ = syscall.revoke_perm(vm_handle);
            _ = syscall.revoke_perm(shm_handle);
            continue;
        }

        const base: [*]volatile u8 = @ptrFromInt(vm.val2);
        var off: u64 = 0;
        while (off < SHM_SIZE) {
            base[off] = 1;
            off += PAGE_SIZE;
        }

        _ = syscall.mem_unmap(vm_handle, 0, SHM_SIZE);
        _ = syscall.revoke_perm(vm_handle);
        _ = syscall.revoke_perm(shm_handle);
    }

    syscall.shutdown();
}
