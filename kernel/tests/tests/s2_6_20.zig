const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.20 — SHM/MMIO mappings within freed reservations do not persist across restart.
/// across restart.
///
/// The child receives an SHM, reserves+maps it on first boot, then faults.
/// The kernel clears all VM reservations on restart (§2.6.6 / §2.6.18).
/// After restart, the child counts VM reservation entries in its perm view
/// BEFORE re-reserving — it must be zero. It records that count into the
/// shared SHM (which still exists per §2.6.12) so the test root can read it.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rights_root = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights_root);
    _ = syscall.mem_shm_map(shm_handle, @bitCast(vm.val), 0);
    const base = vm.val2;
    const run_counter: *volatile u64 = @ptrFromInt(base);
    const vm_before: *volatile u64 = @ptrFromInt(base + 8);
    const vm_after_slot: *volatile u64 = @ptrFromInt(base + 16);
    run_counter.* = 0;
    vm_before.* = 0;
    vm_after_slot.* = 0;

    const child_rights = perms.ProcessRights{
        .restart = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .mem_shm_create = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_vm_count_after_restart.ptr),
        children.child_vm_count_after_restart.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for first boot to record run_counter=1.
    t.waitUntilNonZero(@ptrFromInt(base));

    // Wait for restart to occur.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }

    // Wait for the restarted child to overwrite vm_after_slot. Because it
    // re-maps SHM into a *new* reservation and writes, we poll via SHM.
    // The child writes `vm_count_after + 1`, so 1 == "zero reservations
    // post-restart" — the assertion we care about.
    attempts = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (vm_after_slot.* != 0) break;
        syscall.thread_yield();
    }

    const post_count = vm_after_slot.*; // expected 1 (== vm_count_after+1 with vm_count_after==0)
    const restart_happened = view[slot].processRestartCount() > 0;
    const old_reservations_gone = post_count == 1; // zero VM reservations survived

    if (restart_happened and old_reservations_gone) {
        t.pass("§2.6.20");
    } else {
        t.fail("§2.6.20");
    }
    syscall.shutdown();
}
