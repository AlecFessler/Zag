const app = @import("app");
const lib = @import("lib");

export fn _start(perm_view: u64) noreturn {
    app.main(perm_view);
    lib.syscall.thread_exit();
}
