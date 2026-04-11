const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Reserves one huge VM region and touches pages until OOM kills us.
pub fn main(_: u64) void {
    const size: u64 = 16 * 1024 * 1024 * 1024; // 16 GB — more than QEMU RAM
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.mem_reserve(0, size, rights);
    if (result.val < 0) return;
    const base: [*]volatile u8 = @ptrFromInt(result.val2);
    var offset: u64 = 0;
    while (offset < size) : (offset += 4096) {
        base[offset] = 1;
    }
}
