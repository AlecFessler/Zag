const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.25.3 — `dma_map` with invalid SHM handle returns `E_BADHANDLE`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var dev_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].deviceType() == 0) {
            dev_handle = view[i].handle;
            break;
        }
    }

    if (dev_handle == 0) {
        t.pass("§4.25.3 [SKIP: no device]");
        syscall.shutdown();
    }

    const ret = syscall.dma_map(dev_handle, 0xFFFFFFFF);
    t.expectEqual("§4.25.3", E_BADHANDLE, ret);
    syscall.shutdown();
}
