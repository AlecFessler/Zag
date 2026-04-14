const lib = @import("lib");

const syscall = lib.syscall;

pub fn main(_: u64) void {
    while (true) syscall.thread_yield();
}
