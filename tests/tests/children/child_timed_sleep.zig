const lib = @import("lib");

const syscall = lib.syscall;

pub fn main(_: u64) void {
    // Block on a timed futex_wait with a long timeout (10 seconds).
    // This occupies one timed waiter slot until the timeout expires
    // or the process is killed.
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, 10_000_000_000);
}
