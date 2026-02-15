const lib = @import("lib");

export fn _start() noreturn {
    lib.syscall.write("Hello from userspace!\n");
    while (true) {
        asm volatile ("pause");
    }
}
