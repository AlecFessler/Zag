const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives a process handle via cap transfer, checks perm_view for it, replies with 1 if found.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    // Scan perm_view for a process handle that isn't HANDLE_SELF (handle 0).
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var found: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
            found = 1;
            break;
        }
    }

    _ = syscall.ipc_reply(&.{found});
}
