const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.52 — `mem_mmio_map` with invalid `vm_handle` returns `E_BADHANDLE`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev_entry = t.requireMmioDevice(view, "§2.3.52");
    const dev_handle = dev_entry.handle;

    const ret = syscall.mem_mmio_map(dev_handle, 0xFFFFFFFF, 0);
    t.expectEqual("§2.3.52", E_BADHANDLE, ret);
    syscall.shutdown();
}
