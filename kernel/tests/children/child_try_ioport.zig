const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives device via cap transfer, tries ioport_read or ioport_write (based on
/// command word), reports result via IPC. word[0] from first recv: 0 = read, 1 = write.
pub fn main(perm_view_addr: u64) void {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Recv device via cap transfer + command word
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const cmd = msg.words[0];
    _ = syscall.ipc_reply(&.{});

    // Find device in our perm view
    var dev_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = entry.handle;
            break;
        }
    }

    var result: i64 = undefined;
    if (cmd == 0) {
        result = syscall.ioport_read(dev_handle, 0, 1);
    } else {
        result = syscall.ioport_write(dev_handle, 0, 1, 0);
    }

    // Report result via IPC
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{@bitCast(result)});
}
