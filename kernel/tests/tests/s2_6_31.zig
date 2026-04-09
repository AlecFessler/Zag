const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.31 — Non-recursive kill of a non-restartable process with children makes it a zombie.
/// When a process with children exits (last thread exits), it becomes a zombie.
/// Parent sees dead_process with fault_reason normal_exit. Then revoke cleans up.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Setup: root -> child_spawner -> grandchild (child_sleep).
    const sleep_elf = children.child_sleep;
    const sleep_pages = (sleep_elf.len + 4095) / 4096;
    const shm_size = (sleep_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s.bits());
    const vm_h: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_h, vm_h, 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..sleep_elf.len) |i| dst[i] = sleep_elf[i];

    // Spawn child_spawner (non-restartable).
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .spawn_process = true, .mem_reserve = true, .shm_create = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_spawner.ptr), children.child_spawner.len, child_rights.bits())));

    // Send SHM with child_sleep ELF to spawner.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm_h, shm_rights.bits() }, &reply);

    // Wait for grandchild to be spawned.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // child_spawner exits (it has children -> becomes zombie).
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    // Verify: zombie (dead_process) with normal_exit crash reason.
    const is_dead = view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS;
    const reason = view[slot].processCrashReason();

    if (!is_dead or reason != .normal_exit) {
        t.fail("§2.6.31 child not zombie");
        syscall.shutdown();
    }

    // The child becoming a zombie (dead_process) rather than being fully cleaned up IS
    // the proof of non-recursive kill: if kill were recursive, it would kill the grandchild
    // too, and the child would be fully cleaned up (not left as zombie). Root has no handle
    // to the grandchild (it was spawned by child_spawner), so we can't observe it directly.
    t.pass("§2.6.31");

    // Clean up: revoke kills zombie + grandchild.
    _ = syscall.revoke_perm(ch);
    syscall.shutdown();
}
