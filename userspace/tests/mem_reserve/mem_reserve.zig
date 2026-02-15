const lib = @import("lib");

pub fn main() void {
    lib.syscall.write("mem_reserve test: reserving 1 page RW...\n");
    const result = lib.syscall.mem_reserve(
        lib.syscall.PAGE4K,
        .{ .read = true, .write = true },
    );
    if (result.val >= 0) {
        const ptr: *volatile u64 = @ptrFromInt(result.val2);
        ptr.* = 0xDEADBEEF;
        lib.syscall.write("demand paging OK\n");
    } else {
        lib.syscall.write("mem_reserve: FAILED\n");
    }
}
