const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("process restart + persistence (S2.11, S4)");
    testRestartWithVerification();
}

fn testRestartWithVerification() void {
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

    const run_counter: *u64 = @ptrFromInt(base);
    run_counter.* = 0;
    var i: usize = 1;
    while (i < 512) : (i += 1) {
        const slot: *u64 = @ptrFromInt(base + i * 8);
        slot.* = 0xFFFF;
    }

    const child_elf = embedded.child_restart_verify;
    const child_rights = (perms.ProcessRights{
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

    // Send SHM handle to child via IPC cap transfer
    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const words = [_]u64{ 0, @intCast(shm_handle), grant_rights };
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(@intCast(proc_handle), &words, &reply);

    t.waitUntilAtLeast(run_counter, 2);

    t.pass("S2.6: restartable child ran 2+ times (restart works)");

    const shm_count_run1: *u64 = @ptrFromInt(base + 24);
    const vm_res_run1: *u64 = @ptrFromInt(base + 32);

    if (shm_count_run1.* >= 1) {
        t.pass("S2.6: SHM perm entries persist across restart");
    } else {
        t.failWithVal("S2.6: SHM count on restart", 1, @as(i64, @bitCast(shm_count_run1.*)));
    }
    if (vm_res_run1.* == 0) {
        t.pass("S2.6: VM reservation entries cleared by resetForRestart");
    } else {
        t.failWithVal("S2.6: VM reservation on restart", 0, @as(i64, @bitCast(vm_res_run1.*)));
    }

    const dr = syscall.disable_restart();
    t.expectEqual("S4.disable_restart: clears restart for self and descendants", 0, dr);

    t.waitForCleanup(@intCast(proc_handle));

    const dr2 = syscall.disable_restart();
    t.expectEqual("S4.disable_restart: already cleared returns E_PERM", -2, dr2);
}
