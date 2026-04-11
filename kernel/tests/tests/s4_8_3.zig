const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.8.3 — `mem_mmio_map` with invalid `vm_handle` returns `E_BADHANDLE`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev_entry = t.requireMmioDevice(view, "§4.8.3");
    const dev_handle = dev_entry.handle;

    const ret = syscall.mem_mmio_map(dev_handle, 0xFFFFFFFF, 0);
    t.expectEqual("§4.8.3", E_BADHANDLE, ret);
    syscall.shutdown();
}
