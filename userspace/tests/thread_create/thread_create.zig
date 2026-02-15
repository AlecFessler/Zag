const lib = @import("lib");

fn worker() void {
    lib.syscall.write("hello from spawned thread!\n");
    lib.syscall.thread_exit();
}

pub fn main() void {
    lib.syscall.write("thread_create test: spawning worker...\n");
    const tid = lib.syscall.thread_create(&worker);
    if (tid >= 0) {
        lib.syscall.write("thread_create OK\n");
    } else {
        lib.syscall.write("thread_create FAILED\n");
    }
}
