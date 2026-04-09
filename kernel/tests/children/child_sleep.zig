const lib = @import("lib");

const syscall = lib.syscall;

pub fn main(_: u64) void {
    // Block indefinitely — stay alive.
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
