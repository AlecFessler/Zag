const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Reserves a read+write (no execute) region, writes a RET instruction, then jumps to it.
pub fn main(_: u64) void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.mem_reserve(0, 4096, rights);
    if (result.val < 0) return;
    const ptr: *volatile u8 = @ptrFromInt(result.val2);
    ptr.* = 0xC3; // RET instruction
    const func: *const fn () void = @ptrFromInt(result.val2);
    func();
}
