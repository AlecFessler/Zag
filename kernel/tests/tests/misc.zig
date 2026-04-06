const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("revoke_perm + disable_restart + clock + write (S2.4, S2.11, S4)");
    testClockGettime();
    testWriteZeroLen();
    testRevokeInvalidHandle();
    testRevokeSelf();
    testRevokeVmReservation();
    testDisableRestartAlreadyCleared();
    testProcCreateRestartWithoutRestart();
    testRevokeShmUnmapsAndClearsSlot();
}

fn testClockGettime() void {
    const t1 = syscall.clock_gettime();
    const t2 = syscall.clock_gettime();
    if (t2 >= t1 and t1 > 0) {
        t.pass("S4.clock_gettime: monotonic and nonzero");
    } else {
        t.fail("S4.clock_gettime: not monotonic or zero");
    }
}

fn testDisableRestartAlreadyCleared() void {
    const rc = syscall.disable_restart();
    t.expectEqual("S4.disable_restart: already cleared returns E_PERM", -2, rc);
}

fn testRevokeInvalidHandle() void {
    const rc = syscall.revoke_perm(99999);
    t.expectEqual("S4.revoke_perm: nonexistent handle returns E_BADCAP", -3, rc);
}

fn testRevokeSelf() void {
    const rc = syscall.revoke_perm(0);
    t.expectEqual("S4.revoke_perm: cannot revoke HANDLE_SELF (E_INVAL)", -1, rc);
}

fn testRevokeVmReservation() void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("setup failed");
        return;
    }
    const handle: u64 = @intCast(result.val);
    const base = result.val2;
    const ptr: *u8 = @ptrFromInt(base);
    ptr.* = 77;
    const rc = syscall.revoke_perm(handle);
    t.expectEqual("S2.3.revoke(vm_reservation): frees pages, removes nodes", 0, rc);
    const rc2 = syscall.revoke_perm(handle);
    t.expectEqual("S2.2: revoked slot cleared, double revoke E_BADCAP", -3, rc2);
}

fn testWriteZeroLen() void {
    const rc = asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@as(u64, 0)),
          [a0] "{rdi}" (@as(u64, 0x1000)),
          [a1] "{rsi}" (@as(u64, 0)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true });
    t.expectEqual("S4.write: len=0 returns E_OK (0 bytes written)", 0, rc);
}

fn testRevokeShmUnmapsAndClearsSlot() void {
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
    _ = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    const ptr: *u64 = @ptrFromInt(vm_result.val2);
    ptr.* = 0xDEAD;
    const rc = syscall.revoke_perm(@intCast(shm_handle));
    t.expectEqual("S2.2: revoke SHM handle unmaps PTEs and clears slot", 0, rc);
    const rc2 = syscall.revoke_perm(@intCast(shm_handle));
    t.expectEqual("S2.2: revoked SHM handle returns E_BADCAP on second revoke", -3, rc2);
}

fn testProcCreateRestartWithoutRestart() void {
    const child_elf = embedded.child_exit;
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .restart = true,
    }).bits();
    const rc = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    t.expectEqual("S4.proc_create: parent without restart cannot grant restart (E_PERM)", -2, rc);
}
