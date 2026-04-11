const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.6 — VM reservation entries are cleared on restart.
/// Uses child_restart_verify which reports whether any VM reservation entries
/// exist in its perm_view after restart. On restart, vm_res_slot should be 0
/// because user-created VM reservations are cleared.
pub fn main(pv: u64) void {
    _ = pv;

    // Create SHM large enough for child_restart_verify's data layout.
    // Layout: base[0]=run_counter, base[8+run*16]=shm_count, base[16+run*16]=vm_res_present
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));

    // Map SHM in parent to read results.
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

    // Send SHM to child on first boot via IPC.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for child to have run at least twice (first boot + one restart).
    const no_timeout: u64 = @bitCast(@as(i64, -1));
    while (run_counter.* < 2) {
        _ = syscall.futex_wait(@ptrFromInt(base), @intCast(run_counter.*), no_timeout);
    }

    // After restart (run_counter >= 2), check vm_res_slot for run 1 (the restart run).
    // run 0 = first boot, run 1 = after restart
    // vm_res_slot for run 1 is at base + 16 + 1*16 = base + 32
    const vm_res_after_restart: *volatile u64 = @ptrFromInt(base + 16 + 1 * 16);

    if (vm_res_after_restart.* == 0) {
        t.pass("§2.6.6");
    } else {
        t.fail("§2.6.6");
    }
    syscall.shutdown();
}
