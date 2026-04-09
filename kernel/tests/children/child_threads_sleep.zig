const lib = @import("lib");

const syscall = lib.syscall;

fn worker() void {
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
    syscall.thread_exit();
}

/// Creates 63 extra threads (64 total per process), all block on futex.
/// Used to exhaust kernel stacks when spawned en masse.
pub fn main(_: u64) void {
    for (0..63) |_| {
        if (syscall.thread_create(&worker, 0, 4) < 0) break;
    }
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
