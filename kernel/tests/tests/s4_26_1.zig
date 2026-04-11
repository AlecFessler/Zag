const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.26.1 — `mem_dma_unmap` returns `E_OK` on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.26.1");
    const dev_handle = dev.handle;

    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, (perms.SharedMemoryRights{ .read = true, .write = true }).bits())));
    _ = syscall.mem_dma_map(dev_handle, shm_h);
    const ret = syscall.mem_dma_unmap(dev_handle, shm_h);
    t.expectEqual("§4.26.1", E_OK, ret);
    syscall.shutdown();
}
