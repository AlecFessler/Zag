const lib = @import("lib");

const syscall = lib.syscall;

var policy: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    // Try to create a VM, then exit immediately.
    // The parent will observe our process becoming dead_process.
    _ = syscall.vm_create(1, @intFromPtr(&policy));
    // Exit (thread_exit or just return).
}
