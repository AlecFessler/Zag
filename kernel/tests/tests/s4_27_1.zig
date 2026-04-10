const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.27.1 — `ioport_read` returns value (non-negative) on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requirePioDevice(view, "§4.27.1");
    const dev_handle = dev.handle;

    const ret = syscall.ioport_read(dev_handle, 0, 1);
    if (ret >= 0) {
        t.pass("§4.27.1");
    } else {
        t.failWithVal("§4.27.1", 0, ret);
    }
    syscall.shutdown();
}
