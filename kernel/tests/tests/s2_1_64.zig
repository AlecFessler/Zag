const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.64 — After restart, `restart_count` in `field0` increments.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);
    const counter: *u64 = @ptrFromInt(vm.val2);

    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_restart_counter.ptr), children.child_restart_counter.len, child_rights.bits())));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for child to restart twice (counter >= 3).
    var attempts: u32 = 0;
    while (counter.* < 3 and attempts < 200000) : (attempts += 1) {
        syscall.thread_yield();
    }

    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            slot = i;
            break;
        }
    }
    const restart_count = view[slot].processRestartCount();
    // After 2 restarts, restart_count should be >= 2.
    if (restart_count >= 2) {
        t.pass("§2.1.64");
    } else {
        t.fail("§2.1.64");
    }
    syscall.shutdown();
}
