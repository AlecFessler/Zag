const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.28.4 — `ioport_write` with bad width returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requirePioDevice(view, "§4.28.4");
    const dev_handle = dev.handle;

    const ret = syscall.ioport_write(dev_handle, 0, 3, 0);
    t.expectEqual("§4.28.4", E_INVAL, ret);
    syscall.shutdown();
}
