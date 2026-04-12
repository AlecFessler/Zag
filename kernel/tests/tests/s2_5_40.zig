const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

/// §2.5.40 — `mem_dma_unmap` with no mapping returns `E_NOENT`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§2.5.40");
    const dev_handle = dev.handle;

    // Create SHM but don't mem_dma_map it, then try to unmap.
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, (perms.SharedMemoryRights{ .read = true, .write = true }).bits())));
    const ret = syscall.mem_dma_unmap(dev_handle, shm_h);
    t.expectEqual("§2.5.40", E_NOENT, ret);
    syscall.shutdown();
}
