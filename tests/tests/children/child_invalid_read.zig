const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Reserves a write-only region and reads from it, triggering invalid_read.
pub fn main(_: u64) void {
    const rights = (perms.VmReservationRights{ .write = true }).bits();
    const result = syscall.mem_reserve(0, 4096, rights);
    if (result.val < 0) return;
    const ptr: *volatile u8 = @ptrFromInt(result.val2);
    _ = ptr.*;
}
