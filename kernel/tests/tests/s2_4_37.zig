const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.4.37 — `mem_dma_map` with non-MMIO device returns `E_INVAL`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requirePioDevice(view, "§2.4.37");
    const dev_handle = dev.handle;

    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, (perms.SharedMemoryRights{ .read = true, .write = true }).bits())));
    const ret = syscall.mem_dma_map(dev_handle, shm_h);
    t.expectEqual("§2.4.37", E_INVAL, ret);
    syscall.shutdown();
}
