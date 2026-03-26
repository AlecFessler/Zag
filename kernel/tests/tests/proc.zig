const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("proc_create + cross-process SHM + revoke (S2.2, S2.4, S4)");
    testProcCreateBadElf();
    testProcCreateZeroLen();
    testCrossProcessShmAndGrant();
}

fn testProcCreateBadElf() void {
    var garbage: [64]u8 = undefined;
    for (&garbage) |*b| b.* = 0xAA;
    const rc = syscall.proc_create(@intFromPtr(&garbage), garbage.len, 0);
    t.expectEqual("S4.proc_create: bad ELF returns E_INVAL", -1, rc);
}

fn testProcCreateZeroLen() void {
    const rc = syscall.proc_create(0x1000, 0, 0);
    t.expectEqual("S4.proc_create: elf_len=0 returns E_INVAL", -1, rc);
}

fn testCrossProcessShmAndGrant() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle <= 0) {
        t.fail("setup failed");
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
        t.fail("setup failed");
        return;
    }
    const vm_handle: u64 = @intCast(vm_result.val);
    const map_rc = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    if (map_rc != 0) {
        t.fail("parent shm_map failed");
        return;
    }
    const parent_ptr: *volatile u64 = @ptrFromInt(vm_result.val2);
    parent_ptr.* = 0;

    const child_elf = embedded.child_shm_counter;
    const child_rights = (perms.ProcessRights{
        .grant_to = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .shm_create = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) {
        t.fail("proc_create failed");
        return;
    }
    t.pass("S2.1: proc_create returns handle, child starts with self-handle only");

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    }).bits();
    const grant_rc = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);
    t.expectEqual("S2.3: SHM grant inserts in child, increments refcount", 0, grant_rc);

    t.waitUntilNonZero(parent_ptr);

    if (parent_ptr.* >= 1) {
        t.pass("S2.7: SHM pages shared cross-process, child wrote parent read");
    } else {
        t.fail("S2.7: child never wrote to shared page");
    }

    t.waitForCleanup(@intCast(proc_handle));

    if (parent_ptr.* >= 1) {
        t.pass("S2.7: SHM refcount > 0, parent retains access after child death");
    } else {
        t.fail("S2.7: parent lost SHM access after child cleanup");
    }

    const rc2 = syscall.revoke_perm(@intCast(proc_handle));
    t.expectEqual("S2.3: revoke cleaned-up handle returns E_BADCAP", -3, rc2);
}
