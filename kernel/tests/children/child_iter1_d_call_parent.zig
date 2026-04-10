const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

/// §2.12.36 helper.
///
/// Protocol:
///   Call 1 (parent → us, cap transfer): parent transfers HANDLE_SELF to us
///     so we have a handle back to the parent. We recv, reply empty.
///   Then: we issue `ipc_call` on the parent handle. This blocks us in the
///     parent's wait queue until the parent issues `ipc_recv`. Once the
///     parent `recv`s our call, the parent's msg_box is in `pending_reply`
///     state. Our call blocks until the parent replies; when it does we
///     exit.
pub fn main(perm_view_addr: u64) void {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Receive parent handle via cap transfer.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    // Find parent handle (a process-type entry other than HANDLE_SELF).
    var parent_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
            parent_handle = entry.handle;
            break;
        }
    }
    if (parent_handle == 0) return;

    // Call into parent — will block until parent replies. Parent drives
    // ipc_recv, putting its msg_box into `pending_reply`, runs the fault
    // box independence check, then replies to unblock us.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(parent_handle, &.{}, &reply);
}
