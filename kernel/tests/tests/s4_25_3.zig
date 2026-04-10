const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.25.3 — `dma_map` with invalid SHM handle returns `E_BADHANDLE`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.25.3");
    const dev_handle = dev.handle;

    const ret = syscall.dma_map(dev_handle, 0xFFFFFFFF);
    t.expectEqual("§4.25.3", E_BADHANDLE, ret);
    syscall.shutdown();
}
