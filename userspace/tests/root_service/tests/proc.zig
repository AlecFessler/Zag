const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("proc_create + grant_perm + revoke_perm(process)");
    testProcCreateBadElf();
    testProcCreateZeroLen();
    testProcCreateAndRevoke();
    testRevokeShm();
}

fn yieldN(n: u32) void {
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        syscall.thread_yield();
    }
}

fn testProcCreateAndRevoke() void {
    const child_elf = embedded.child_exit;
    const child_rights = (perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .shm_create = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) {
        t.failWithVal("proc_create: spawn failed", 1, proc_handle);
        return;
    }
    t.pass("proc_create: basic child spawn");

    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle > 0) {
        const grant_rights = (perms.SharedMemoryRights{
            .read = true,
            .write = true,
            .grant = true,
        }).bits();
        const grant_rc = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);
        t.expectEqual("grant_shm: grant SHM to child", 0, grant_rc);
    }

    const rc = syscall.revoke_perm(@intCast(proc_handle));
    t.expectEqual("proc_revoke: kills child", 0, rc);

    yieldN(5000);

    const rc2 = syscall.revoke_perm(@intCast(proc_handle));
    t.expectEqual("proc_revoke: double revoke returns E_BADCAP", -3, rc2);
}

fn testProcCreateBadElf() void {
    var garbage: [64]u8 = undefined;
    for (&garbage) |*b| b.* = 0xAA;
    const rc = syscall.proc_create(@intFromPtr(&garbage), garbage.len, 0);
    t.expectEqual("proc_create: bad ELF rejected", -1, rc);
}

fn testProcCreateZeroLen() void {
    const rc = syscall.proc_create(0x1000, 0, 0);
    t.expectEqual("proc_create: zero length rejected", -1, rc);
}

fn testRevokeShm() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle <= 0) {
        t.failWithVal("revoke_shm: shm_create failed", 1, shm_handle);
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
        t.failWithVal("revoke_shm: vm_reserve failed", 0, vm_result.val);
        return;
    }
    const vm_handle: u64 = @intCast(vm_result.val);

    const map_rc = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    if (map_rc != 0) {
        t.failWithVal("revoke_shm: shm_map failed", 0, map_rc);
        return;
    }

    const rc = syscall.revoke_perm(@intCast(shm_handle));
    t.expectEqual("revoke_shm: revoke mapped SHM succeeds", 0, rc);
}
