const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

/// Target process used by §2.12.35 test.
///
/// Protocol:
///   Call 1 (parent → us, cap transfer): parent transfers a process handle
///     to the handler process. We receive it, look it up in our perm view,
///     reply with empty payload, then issue our own ipc_call to the handler
///     with a HANDLE_SELF + fault_handler cap transfer — making the handler
///     our external fault handler (§2.12.3).
///   Call 2+ (parent → us, no cap transfer): we reply with our current
///     slot 0 ProcessRights (the fault_handler bit flips off once the
///     handler owns it, then back on after the handler dies).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // --- Call 1: receive handler handle via cap transfer ---
    var msg1: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg1);

    // Find the process handle the kernel just inserted into our perm table.
    // Skip slot 0 (HANDLE_SELF).
    var handler_handle: u64 = 0;
    for (1..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != 0) {
            handler_handle = view[i].handle;
            break;
        }
    }
    _ = syscall.ipc_reply(&.{});

    if (handler_handle == 0) return;

    // Transfer HANDLE_SELF + fault_handler to the handler via ipc_call.
    // Per §2.12.3 this atomically installs the handler as our external
    // fault handler and clears our slot-0 fault_handler bit.
    const fh_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(handler_handle, &.{ 0, fh_rights }, &reply);

    // --- Subsequent calls: report our slot 0 rights ---
    while (true) {
        var m: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &m) != 0) return;
        const rights: u64 = view[0].rights;
        _ = syscall.ipc_reply(&.{rights});
    }
}
