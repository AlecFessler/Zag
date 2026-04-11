const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.26 — On restart, fault reason and restart count are written to both the process's own slot 0 and the parent's entry for the child.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Use child_stack_overflow_restart: crashes with stack overflow on first boot,
    // then on restart reads its OWN view[0].processCrashReason() and processRestartCount()
    // and writes them to SHM. This verifies both the child-side and parent-side values.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights);
    if (vm.val < 0) {
        t.fail("§2.6.26");
        syscall.shutdown();
    }
    _ = syscall.mem_shm_map(shm_handle, @bitCast(vm.val), 0);
    const base: [*]volatile u64 = @ptrFromInt(vm.val2);
    base[0] = 0;
    base[1] = 0;
    base[2] = 0;

    const child_rights = (perms.ProcessRights{ .restart = true, .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_stack_overflow_restart.ptr),
        children.child_stack_overflow_restart.len,
        child_rights,
    )));

    // Send SHM to child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for first boot (run_counter = 1).
    t.waitUntilNonZero(@ptrFromInt(vm.val2));

    // Wait for restart and crash info written by child (base+8 = crash_reason from child's own slot 0).
    t.waitUntilNonZero(@ptrFromInt(vm.val2 + 8));

    // Read child-side values (from child's own slot 0).
    const child_crash_reason = base[1]; // written by child from its view[0]
    const child_restart_count = base[2]; // written by child from its view[0]

    // Read parent-side values.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    const parent_crash_reason = @intFromEnum(view[slot].processCrashReason());
    const parent_restart_count = view[slot].processRestartCount();

    // Both sides should agree: crash_reason = stack_overflow (1), restart_count > 0.
    const child_ok = child_crash_reason == 1 and child_restart_count > 0;
    const parent_ok = parent_crash_reason == 1 and parent_restart_count > 0;
    if (child_ok and parent_ok) {
        t.pass("§2.6.26");
    } else {
        t.fail("§2.6.26");
    }
    syscall.shutdown();
}
