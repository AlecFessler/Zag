const lib = @import("lib");

const syscall = lib.syscall;

/// Writes to the perm_view page, which should be read-only.
/// Expected to fault with invalid_write.
pub fn main(pv: u64) void {
    // Signal parent we're about to write.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});
    // Write to the perm_view page — should fault.
    const ptr: *volatile u8 = @ptrFromInt(pv);
    ptr.* = 0;
}
