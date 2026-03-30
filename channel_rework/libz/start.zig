const app = @import("app");
const lib = @import("lib");

export fn _start(perm_view_addr: u64) noreturn {
    const is_root = @hasDecl(app, "is_root") and app.is_root;
    if (!is_root) {
        initAsChild(perm_view_addr);
    }
    app.main(perm_view_addr);
    lib.syscall.thread_exit();
}

fn initAsChild(perm_view_addr: u64) void {
    lib.channel.perm_view_addr = perm_view_addr;
    const view: *const [128]lib.perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);
    lib.channel.initParentSHMs(view);
    lib.channel.initSemanticId();
    _ = lib.syscall.thread_create(&lib.channel.workerMain, 0, 4);
}
