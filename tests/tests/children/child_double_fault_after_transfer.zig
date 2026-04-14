const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Receives IPC, replies with HANDLE_SELF via cap transfer with fault_handler
/// bit set, then executes two consecutive null-deref instructions at distinct
/// target addresses. Used by §2.12.26 to verify FAULT_RESUME_MODIFIED: after
/// the parent receives the first fault (at address 0), it advances RIP by 2
/// to skip the first instruction; the second instruction then faults at
/// address 0xCAFE0000, which the parent observes as a distinct fault.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    const rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, rights });

    // Two consecutive null-deref faults at distinct addresses. The parent
    // will skip past the first by advancing the faulting thread's PC via
    // FAULT_RESUME_MODIFIED.
    const a: *allowzero volatile u8 = @ptrFromInt(0);
    _ = a.*;
    const b: *volatile u8 = @ptrFromInt(0xCAFE0000);
    _ = b.*;
}
