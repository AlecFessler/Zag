const app = @import("app");
const lib = @import("lib");

export fn _start(perm_view_addr: u64) noreturn {
    app.main(perm_view_addr);
    lib.syscall.thread_exit();
}
