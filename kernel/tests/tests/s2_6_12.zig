const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.12 — SHM handle entries persist across restart.
/// child_restart_counter: on first boot receives SHM via IPC; on restart it finds the
/// SHM entry directly in its own perm_view (no IPC needed). If the counter increments
/// on the second run, the SHM handle entry persisted across restart.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create SHM and map it in parent to read the run counter.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    const counter: *u64 = @ptrFromInt(vm.val2);

    // Spawn restartable child_restart_counter.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_restart_counter.ptr), children.child_restart_counter.len, child_rights.bits())));

    // Send SHM to child on first boot via IPC.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for counter >= 2: child ran, exited, restarted, and ran again using the
    // persisted SHM entry from perm_view — no second IPC needed.
    var attempts: u32 = 0;
    while (counter.* < 2 and attempts < 200000) : (attempts += 1) {
        syscall.thread_yield();
    }

    // Find slot to confirm child is alive.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // counter >= 2 means the child ran twice; since it only receives SHM on first boot,
    // the second run found the SHM entry in its persisted perm table.
    if (counter.* >= 2 and view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
        t.pass("§2.6.12");
    } else {
        t.fail("§2.6.12");
    }
    syscall.shutdown();
}
