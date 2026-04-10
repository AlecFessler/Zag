const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.27.5 — `ioport_read` with `offset + width > port_count` returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requirePioDevice(view, "§4.27.5");
    const dev_handle = dev.handle;
    const port_count: u32 = dev.deviceSizeOrPortCount();

    // Read at offset = port_count, width = 1 => offset + width > port_count.
    const ret = syscall.ioport_read(dev_handle, @as(u64, port_count), 1);
    t.expectEqual("§4.27.5", E_INVAL, ret);
    syscall.shutdown();
}
