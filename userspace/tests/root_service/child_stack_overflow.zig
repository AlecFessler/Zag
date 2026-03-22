const lib = @import("lib");

const syscall = lib.syscall;

fn recurse(depth: u64) u64 {
    if (depth == 0) return 0;
    var buf: [512]u8 = undefined;
    buf[0] = @truncate(depth);
    return buf[0] + recurse(depth - 1);
}

pub fn main(_: u64) void {
    syscall.write("stack_overflow: about to recurse\n");
    _ = recurse(100_000);
    syscall.write("stack_overflow: should not reach here\n");
}
