const lib = @import("lib");

pub fn main(_: u64) void {
    lib.syscall.write("child_exit: alive\n");
}
