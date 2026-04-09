const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.21 — Process entry `field0` encodes `fault_reason(u5, bits 0-4) | restart_count(u16, bits 16-31)`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create SHM for restart counter child.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);
    const counter: *u64 = @ptrFromInt(vm.val2);

    // Spawn restartable child.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_restart_counter.ptr), children.child_restart_counter.len, child_rights.bits())));

    // Send SHM to child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for at least one restart (counter >= 2).
    var attempts: u32 = 0;
    while (counter.* < 2 and attempts < 100000) : (attempts += 1) {
        syscall.thread_yield();
    }

    // Check the parent's entry for this child.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            slot = i;
            break;
        }
    }
    const crash_reason = view[slot].processCrashReason();
    const restart_count = view[slot].processRestartCount();

    // After restart: fault_reason should be normal_exit (12), restart_count >= 1.
    if (crash_reason == .normal_exit and restart_count >= 1) {
        t.pass("§2.1.21");
    } else {
        t.fail("§2.1.21");
    }
    syscall.shutdown();
}
