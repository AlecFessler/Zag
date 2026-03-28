const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("zombie process + process tree depth (S2.2)");
    testZombieChain();
}

fn testZombieChain() void {
    const child_exit_elf = embedded.child_exit;
    const spawner_elf = embedded.child_spawner;

    const shm_size = child_exit_elf.len + syscall.PAGE4K;
    const aligned_size = ((shm_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;

    const shm_handle = syscall.shm_create(aligned_size);
    if (shm_handle <= 0) {
        t.fail("setup: shm_create failed");
        return;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, aligned_size, vm_rights);
    if (vm_result.val < 0) {
        t.fail("setup: vm_reserve failed");
        return;
    }
    const vm_handle: u64 = @intCast(vm_result.val);
    _ = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);

    const dest: [*]u8 = @ptrFromInt(vm_result.val2);
    for (0..child_exit_elf.len) |i| {
        dest[i] = child_exit_elf[i];
    }

    const signal_ptr: *volatile u64 = @ptrFromInt(vm_result.val2 + aligned_size - 8);
    signal_ptr.* = 0;

    const child_rights = (perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(spawner_elf.ptr), spawner_elf.len, child_rights);
    if (proc_handle <= 0) {
        t.fail("proc_create for spawner failed");
        return;
    }

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .execute = true,
        .grant = true,
    }).bits();
    _ = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);

    t.waitUntilNonZero(signal_ptr);

    if (signal_ptr.* == 1) {
        t.waitForCleanup(@intCast(proc_handle));
        t.pass("S2.1: 3-level process tree created, subtree fully cleaned up");
    } else if (signal_ptr.* == 0xDEAD) {
        t.fail("S2.1: spawner child failed to create grandchild");
        t.waitForCleanup(@intCast(proc_handle));
    } else {
        t.fail("S2.1: spawner returned unexpected signal");
        t.waitForCleanup(@intCast(proc_handle));
    }
}
