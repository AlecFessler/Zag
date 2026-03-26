const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("shm_create + shm_map + shm_unmap");
    testShmCreateBasic();
    testShmMapWriteReadUnmap();
    testShmUnmapRestoresPrivateAccess();
}

fn testShmCreateBasic() void {
    const rc = syscall.shm_create(syscall.PAGE4K);
    t.expectOk("S2.7: shm_create allocates zeroed pages, returns handle", rc);
}

fn testShmMapWriteReadUnmap() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
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
    const base = vm_result.val2;
    const map_rc = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    if (map_rc != 0) {
        t.failWithVal("shm_map failed", 0, map_rc);
        return;
    }
    const ptr: *volatile u64 = @ptrFromInt(base);
    ptr.* = 0xDEADBEEF;
    if (ptr.* != 0xDEADBEEF) {
        t.fail("write/read through SHM failed");
        return;
    }
    const unmap_rc = syscall.shm_unmap(@intCast(shm_handle), vm_handle);
    t.expectEqual("S2.2.shm_map: eagerly maps all pages; unmap succeeds", 0, unmap_rc);
}

fn testShmUnmapRestoresPrivateAccess() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle < 0) {
        t.fail("setup failed");
        return;
    }
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, 2 * syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) {
        t.fail("setup failed");
        return;
    }
    const vm_handle: u64 = @intCast(vm_result.val);
    const base = vm_result.val2;
    _ = syscall.shm_map(@intCast(shm_handle), vm_handle, 0);
    _ = syscall.shm_unmap(@intCast(shm_handle), vm_handle);
    const ptr: *volatile u8 = @ptrFromInt(base);
    ptr.* = 99;
    const ptr2: *volatile u8 = @ptrFromInt(base + syscall.PAGE4K);
    ptr2.* = 100;
    if (ptr.* == 99 and ptr2.* == 100) {
        t.pass("S2.2.shm_unmap: reverts to private, max_rights RWX restored");
    } else {
        t.fail("S2.2.shm_unmap: private access failed after unmap");
    }
}
