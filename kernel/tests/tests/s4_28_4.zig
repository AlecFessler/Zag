const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.28.4 — `ioport_write` with bad width returns `E_INVAL`.
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
        t.pass("§4.28.4 [SKIP: no device]");
        syscall.shutdown();
    }

    const ret = syscall.ioport_write(dev_handle, 0, 3, 0);
    t.expectEqual("§4.28.4", E_INVAL, ret);
    syscall.shutdown();
}
