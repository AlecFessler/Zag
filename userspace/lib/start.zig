const app = @import("app");
const lib = @import("lib");

export fn _start() noreturn {
    app.main();
    lib.syscall.thread_exit();
}
