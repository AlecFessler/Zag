const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Tries proc_create (with dummy ELF ptr) and reports result via IPC reply.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    // Use our own code address (mapped, readable) as the ELF pointer.
    // It's not a valid ELF but should pass address validation.
    // The perm check for spawn_process should reject before ELF parsing.
    const child_rights = perms.ProcessRights{};
    const rc = syscall.proc_create(@intFromPtr(&main), 256, child_rights.bits());
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}
