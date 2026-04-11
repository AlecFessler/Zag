const lib = @import("lib");

const syscall = lib.syscall;

/// Single-threaded child that is its own fault handler (no cap transfer
/// to parent). Starts PMU with an overflow threshold on itself and burns
/// instructions until the overflow fires. Per §2.14.14 the kernel must
/// kill the process.
pub fn main(_: u64) void {
    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{
        .event = @intFromEnum(syscall.PmuEvent.instructions),
        .overflow_threshold = 1024,
    };
    _ = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    var x: u64 = 0;
    while (true) : (x +%= 1) {}
}
