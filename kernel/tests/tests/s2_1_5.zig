const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.5 — A process with a restart context restarts instead of becoming a zombie.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create SHM for the child to use as a restart counter.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Map SHM in parent to read the counter.
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    const counter: *u64 = @ptrFromInt(vm.val2);

    // Spawn child_restart_counter with restart enabled.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_restart_counter.ptr), children.child_restart_counter.len, child_rights.bits())));

    // Send SHM handle to child via IPC.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for child to restart at least once (counter >= 2 means it ran, exited, restarted, ran again).
    // Poll since child doesn't futex_wake.
    var attempts: u32 = 0;
    while (counter.* < 2 and attempts < 100000) : (attempts += 1) {
        syscall.thread_yield();
    }

    // Verify child's entry is still 'process' (not dead_process) — it restarted.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
        t.pass("§2.1.5");
    } else {
        t.fail("§2.1.5");
    }
    syscall.shutdown();
}
