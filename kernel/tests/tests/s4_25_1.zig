const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.25.1 — `mem_dma_map` returns DMA base address (positive) on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "§4.25.1");
    const dev_handle = dev.handle;

    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, (perms.SharedMemoryRights{ .read = true, .write = true }).bits())));
    const ret = syscall.mem_dma_map(dev_handle, shm_h);
    if (ret > 0) {
        t.pass("§4.25.1");
    } else {
        t.failWithVal("§4.25.1", 1, ret);
    }
    syscall.shutdown();
}
