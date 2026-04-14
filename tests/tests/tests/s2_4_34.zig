const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.4.34 — `mem_dma_map` with invalid device handle returns `E_BADHANDLE`.
pub fn main(_: u64) void {
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, (perms.SharedMemoryRights{ .read = true, .write = true }).bits())));
    const ret = syscall.mem_dma_map(0xFFFFFFFF, shm_h);
    t.expectEqual("§2.4.34", E_BADHANDLE, ret);
    syscall.shutdown();
}
