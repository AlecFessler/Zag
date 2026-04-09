const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.23 — After restart, `crash_reason` in `field0` reflects the triggering fault.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create SHM for communication.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);

    // Spawn restartable child that causes stack overflow.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_stack_overflow_restart.ptr), children.child_stack_overflow_restart.len, child_rights.bits())));

    // Send SHM to child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for child to report crash info after restart (crash_reason_slot at base+8).
    const crash_reason_ptr: *u64 = @ptrFromInt(vm.val2 + 8);
    t.waitUntilNonZero(crash_reason_ptr);

    // Also check the PARENT's view of the child's entry.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    const parent_crash_reason = view[slot].processCrashReason();

    // Stack overflow should give crash reason = stack_overflow (1).
    if (parent_crash_reason == .stack_overflow) {
        t.pass("§2.1.23");
    } else {
        t.fail("§2.1.23");
    }
    syscall.shutdown();
}
