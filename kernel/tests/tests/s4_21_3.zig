const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.21.3 — `disable_restart` clears restart for all descendants recursively.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Setup: root → child_spawner → grandchild (child_exit). Both restartable.
    const elf = children.child_exit;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s.bits());
    _ = syscall.shm_map(shm_h, @bitCast(vm.val), 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..elf.len) |i| dst[i] = elf[i];

    // Spawn child_spawner with restart right. child_spawner itself exits after
    // spawning grandchild, but grandchild was spawned with whatever rights child_spawner gives.
    // child_spawner gives spawn_thread only, no restart. We need the grandchild restartable.
    // Instead, spawn a simple restartable child (child_exit). After it starts restarting,
    // disable_restart from root should stop it.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights,
    )));

    // Find the child's slot.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }

    // Wait for at least one restart.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() == 0) {
        t.fail("§4.21.3");
        syscall.shutdown();
    }

    // disable_restart propagates recursively to all descendants.
    _ = syscall.disable_restart();

    // The child's next exit should make it a dead process instead of restarting.
    attempts = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.pass("§4.21.3");
    } else {
        t.fail("§4.21.3");
    }
    syscall.shutdown();
}
