const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.17 — User permissions view (mapped read-only region) persists across restart.
/// child_restart_counter reads its own perm_view on every run (including after restart)
/// to find its SHM handle. If the perm_view mapping did not persist, the child would
/// crash or fail to find the SHM — proven by counter reaching >= 2.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    const counter: *u64 = @ptrFromInt(vm.val2);

    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_restart_counter.ptr), children.child_restart_counter.len, child_rights.bits())));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for second run — child used perm_view after restart to re-acquire SHM.
    var attempts: u32 = 0;
    while (counter.* < 2 and attempts < 200000) : (attempts += 1) {
        syscall.thread_yield();
    }

    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // If the perm_view mapping persisted, child found SHM and incremented counter twice.
    if (counter.* >= 2 and view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
        t.pass("§2.6.17");
    } else {
        t.fail("§2.6.17");
    }
    syscall.shutdown();
}
