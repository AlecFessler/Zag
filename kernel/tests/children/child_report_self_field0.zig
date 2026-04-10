const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;

/// Replies with its own slot 0 (HANDLE_SELF) process entry's field0.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{view[0].field0});
}
