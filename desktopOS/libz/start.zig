const app = @import("app");
const lib = @import("lib");

export fn _start(perm_view_addr: u64) noreturn {
    const is_root = @hasDecl(app, "is_root") and app.is_root;
    if (!is_root) {
        lib.channel.perm_view_addr = perm_view_addr;
    }
    app.main(perm_view_addr);
    lib.syscall.thread_exit();
}
