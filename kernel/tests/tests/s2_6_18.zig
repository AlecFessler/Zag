const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.18 — User-created VM reservations do not persist across restart.
/// Uses child_restart_verify which creates a VM reservation each run, then
/// records whether any pre-existing VM reservation entries were found on restart.
/// After restart, vm_res_present should be 0 (no leftover reservations).
pub fn main(pv: u64) void {
    _ = pv;

    // Create SHM for child_restart_verify data.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Map SHM in parent.
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);

    const base = vm.val2;
    const run_counter: *volatile u64 = @ptrFromInt(base);

    // Zero the SHM.
    const dst: [*]volatile u8 = @ptrFromInt(base);
    for (0..4096) |i| dst[i] = 0;

    // Spawn restartable child_restart_verify.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_restart_verify.ptr), children.child_restart_verify.len, child_rights.bits())));

    // Send SHM to child on first boot.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for at least 2 runs.
    const no_timeout: u64 = @bitCast(@as(i64, -1));
    while (run_counter.* < 2) {
        _ = syscall.futex_wait(@ptrFromInt(base), @intCast(run_counter.*), no_timeout);
    }

    // Check vm_res_present for the restart run (run index 1).
    // Layout: base[16 + run*16] = vm_res_present
    const vm_res_after_restart: *volatile u64 = @ptrFromInt(base + 16 + 1 * 16);

    if (vm_res_after_restart.* == 0) {
        t.pass("§2.6.18");
    } else {
        t.fail("§2.6.18");
    }
    syscall.shutdown();
}
