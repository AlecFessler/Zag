const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.27.4 — `ioport_read` with bad width (not 1, 2, or 4) returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requirePioDevice(view, "§4.27.4");
    const dev_handle = dev.handle;

    const ret = syscall.ioport_read(dev_handle, 0, 3);
    t.expectEqual("§4.27.4", E_INVAL, ret);
    syscall.shutdown();
}
