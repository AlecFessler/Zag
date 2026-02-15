const lib = @import("lib");

export fn _start() noreturn {
    lib.syscall.write("Hello from userspace!\n");
    lib.syscall.thread_exit();
}
