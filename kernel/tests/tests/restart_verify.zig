const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("restart persistence verification (S2.6)");
    testRestartClearsVmPreservesShm();
}

fn testRestartClearsVmPreservesShm() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
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
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) {
        t.fail("setup: vm_reserve failed");
        return;
    }
    _ = syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0);
    const base = vm_result.val2;

    const run_counter: *volatile u64 = @ptrFromInt(base);
    run_counter.* = 0;

    var i: usize = 1;
    while (i < 512) : (i += 1) {
        const slot: *volatile u64 = @ptrFromInt(base + i * 8);
        slot.* = 0xFFFF;
    }

    const child_elf = embedded.child_restart_verify;
    const child_rights = (perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .shm_create = true,
        .restart = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) {
        t.fail("proc_create failed");
        return;
    }
    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    _ = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);

    var spins: u32 = 0;
    while (run_counter.* < 2 and spins < 500_000) : (spins += 1) {
        syscall.thread_yield();
    }

    if (run_counter.* >= 2) {
        const shm_count_run0: *volatile u64 = @ptrFromInt(base + 8);
        const vm_res_run0: *volatile u64 = @ptrFromInt(base + 16);
        const shm_count_run1: *volatile u64 = @ptrFromInt(base + 24);
        const vm_res_run1: *volatile u64 = @ptrFromInt(base + 32);

        if (shm_count_run1.* >= 1) {
            t.pass("S2.6: SHM perm entries persist across restart");
        } else {
            t.failWithVal("S2.6: SHM count on restart", 1, @as(i64, @bitCast(shm_count_run1.*)));
        }
        if (vm_res_run1.* == 0) {
            t.pass("S2.6: VM reservation entries cleared by resetForRestart");
        } else {
            t.failWithVal("S2.6: VM reservation entries on restart", 0, @as(i64, @bitCast(vm_res_run1.*)));
        }
        _ = shm_count_run0;
        _ = vm_res_run0;
    } else {
        t.fail("S2.6: child did not restart (counter < 2)");
    }

    _ = syscall.disable_restart();
    t.waitForCleanup(@intCast(proc_handle));
}
