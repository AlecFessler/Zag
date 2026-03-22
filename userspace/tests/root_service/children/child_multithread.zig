const lib = @import("lib");

const syscall = lib.syscall;

fn workerThread() void {
    var i: u32 = 0;
    while (i < 1_000_000) : (i += 1) {
        syscall.thread_yield();
    }
    syscall.thread_exit();
}

pub fn main(_: u64) void {
    _ = syscall.thread_create(&workerThread, 0, 4);
    _ = syscall.thread_create(&workerThread, 0, 4);

    var i: u32 = 0;
    while (i < 1_000_000) : (i += 1) {
        syscall.thread_yield();
    }
}
