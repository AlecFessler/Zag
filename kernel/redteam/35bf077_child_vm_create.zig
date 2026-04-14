// Child for 35bf077 PoC. Spawned with empty ProcessRights (no vm_create).
// Calls vm_create(), then replies to the parent's ipc_call with the
// vm_create return value as word 0.
const lib = @import("lib");
const syscall = lib.syscall;

// 4 KiB zero-filled VmPolicy buffer — matches what other PoCs and tests use.
var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

    const rc = syscall.vm_create(1, @intFromPtr(&policy));
    const word: u64 = @bitCast(rc);

    _ = syscall.ipc_reply(&.{word});
    syscall.thread_exit();
}
