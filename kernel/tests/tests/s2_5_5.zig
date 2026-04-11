const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.5 — Cross-process futexes work over shared memory (two processes mapping the same SHM can synchronize via the same address).
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    const ptr: *u64 = @ptrFromInt(vm.val2);

    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_shm_writer.ptr), children.child_shm_writer.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Use futex_wait to block until the child writes and wakes us.
    // expected=0: if the value is still 0 (child hasn't written yet), we sleep.
    // The child writes 0xDEAD_BEEF then calls futex_wake on its own VA mapping
    // of the same SHM, which wakes us because both VAs resolve to the same PA.
    _ = syscall.futex_wait(@ptrCast(ptr), 0, ~@as(u64, 0));

    if (ptr.* == 0xDEAD_BEEF) {
        t.pass("§2.5.5");
    } else {
        t.fail("§2.5.5");
    }
    syscall.shutdown();
}
