const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives parent handle via cap transfer, then calls parent with HANDLE_SELF cap transfer.
/// Used to test E_MAXCAP when parent's perm table is full at recv time.
pub fn main(perm_view_addr: u64) void {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Recv parent handle via cap transfer
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    // Find parent handle (process type, not HANDLE_SELF)
    var parent_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
            parent_handle = entry.handle;
            break;
        }
    }
    if (parent_handle == 0) return;

    // Call parent with HANDLE_SELF cap transfer
    const rights: u64 = (perms.ProcessHandleRights{ .send_words = true }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(parent_handle, &.{ 0, rights }, &reply);
}
