const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives a handle to grandparent A via IPC cap transfer.
/// Calls A with HANDLE_SELF so A gets a handle to us.
/// Then waits for A to call us and replies.
pub fn main(perm_view_addr: u64) void {
    // Receive cap transfer from parent B — gives us a process handle to A
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    // Find the process handle to A in our perm view
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var a_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_PROCESS and entry.handle != 0) {
            a_handle = entry.handle;
            break;
        }
    }
    if (a_handle == 0) return;

    // Call A with HANDLE_SELF — A now gets a handle to us (C)
    const all_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(a_handle, &.{ 0, all_rights }, &reply);

    // Now wait for A to call us (liveness check after B is killed)
    var msg2: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg2) != 0) return;
    _ = syscall.ipc_reply(&.{0xA11CE});
}
