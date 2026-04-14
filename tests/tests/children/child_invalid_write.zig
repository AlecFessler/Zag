const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Reserves a read-only region and writes to it, triggering invalid_write.
pub fn main(_: u64) void {
    const rights = (perms.VmReservationRights{ .read = true }).bits();
    const result = syscall.mem_reserve(0, 4096, rights);
    if (result.val < 0) return;
    const ptr: *volatile u8 = @ptrFromInt(result.val2);
    ptr.* = 0;
}
