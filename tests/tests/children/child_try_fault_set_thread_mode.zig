const lib = @import("lib");

const syscall = lib.syscall;

fn loopForever() void {
    while (true) {
        lib.fault.cpuPause();
    }
}

/// Creates a thread, receives IPC from parent, calls `fault_set_thread_mode`
/// on the child's own thread, and replies with the result. Used to test
/// §4.37.2 E_PERM: spawn this child WITHOUT `fault_handler` ProcessRights so
/// that the child does not hold fault_handler over its own process.
pub fn main(_: u64) void {
    const ret = syscall.thread_create(&loopForever, 0, 4);
    if (ret <= 0) {
        var msg: syscall.IpcMessage = .{};
        _ = syscall.ipc_recv(true, &msg);
        _ = syscall.ipc_reply(&.{@bitCast(@as(i64, -999))});
        return;
    }
    const thread_handle: u64 = @bitCast(ret);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

    const rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
