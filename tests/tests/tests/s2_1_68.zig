const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.68 — `shared_memory` entry: `field0` = size.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const size: u64 = 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(size, shm_rights.bits()));
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            if (view[i].field0 == size) {
                found = true;
            }
            break;
        }
    }
    if (found) {
        t.pass("§2.1.68");
    } else {
        t.fail("§2.1.68");
    }
    syscall.shutdown();
}
