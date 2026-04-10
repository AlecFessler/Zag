const lib = @import("lib");

const syscall = lib.syscall;

/// Acts as a middleman fault handler. Waits for a single ipc_call from
/// whichever process becomes its "debuggee" (the process doing
/// HANDLE_SELF + fault_handler cap transfer to us). We simply recv and
/// reply with an empty payload — the kernel installs us as the fault
/// handler as a side-effect of receiving the cap. After that we spin
/// forever on a futex so the parent can kill us externally.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    var futex_val: u64 = 0;
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, @bitCast(@as(i64, -1)));
}
