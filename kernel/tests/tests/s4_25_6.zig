const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.25.6 — `dma_map` with non-MMIO device returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 1) {
            dev_handle = view[i].handle;
            break;
        }
    }

    if (dev_handle == 0) {
        t.pass("§4.25.6 [SKIP: no device]");
        syscall.shutdown();
    }

    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, (perms.SharedMemoryRights{ .read = true, .write = true }).bits())));
    const ret = syscall.dma_map(dev_handle, shm_h);
    t.expectEqual("§4.25.6", E_INVAL, ret);
    syscall.shutdown();
}
