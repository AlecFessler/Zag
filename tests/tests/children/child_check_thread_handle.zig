const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;

/// Checks its own perm_view for thread handle entries and reports count via IPC.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    var thread_count: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_count += 1;
        }
    }
    _ = syscall.ipc_reply(&.{thread_count});
}
