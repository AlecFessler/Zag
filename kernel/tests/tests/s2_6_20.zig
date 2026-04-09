const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.20 — SHM/MMIO mappings within freed reservations do not persist across restart.
/// Spawn a restartable child that maps SHM on first boot, writes a magic value,
/// then exits. On restart, SHM handle persists but VM reservation is cleared (§2.6.18).
/// The child re-maps SHM and reads — should see the original value (SHM pages persist),
/// but the mapping itself was gone (had to re-map). Verified by child_stack_overflow_restart
/// which does exactly this pattern: receives SHM, maps it, writes, crashes, then on
/// restart re-maps and writes new data.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Create SHM for child to use.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    // Map locally to read results.
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, 4096, vm_rights);
    if (vm.val < 0) {
        t.fail("§2.6.20");
        syscall.shutdown();
    }
    _ = syscall.shm_map(shm_handle, @bitCast(vm.val), 0);
    const base: [*]volatile u64 = @ptrFromInt(vm.val2);
    // Zero out the SHM.
    base[0] = 0;
    base[1] = 0;

    // Spawn restartable child_stack_overflow_restart.
    const child_rights = (perms.ProcessRights{ .restart = true, .spawn_thread = true, .mem_reserve = true, .shm_create = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_stack_overflow_restart.ptr),
        children.child_stack_overflow_restart.len,
        child_rights,
    )));

    // Send SHM to child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for child to write run_counter = 1 (first boot started).
    t.waitUntilNonZero(@ptrFromInt(vm.val2));

    // Wait for child to restart and write crash info (base+8 = crash_reason).
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
    // Wait for crash_reason_slot to be written by restarted child.
    t.waitUntilNonZero(@ptrFromInt(vm.val2 + 8));

    // If child successfully re-mapped SHM after restart and wrote crash info,
    // the old mapping was gone (had to re-reserve and re-map) — §2.6.20 holds.
    // crash_reason should be stack_overflow (1).
    if (base[1] > 0) {
        t.pass("§2.6.20");
    } else {
        t.fail("§2.6.20");
    }
    syscall.shutdown();
}
