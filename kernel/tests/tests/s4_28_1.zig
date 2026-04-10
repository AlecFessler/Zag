const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.28.1 — `ioport_write` returns `E_OK` on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requirePioDevice(view, "§4.28.1");
    const dev_handle = dev.handle;

    const ret = syscall.ioport_write(dev_handle, 0, 1, 0);
    t.expectEqual("§4.28.1", E_OK, ret);
    syscall.shutdown();
}
