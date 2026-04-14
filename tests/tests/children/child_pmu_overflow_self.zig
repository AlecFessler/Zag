const lib = @import("lib");

const syscall = lib.syscall;

/// Single-threaded child that is its own fault handler (no cap transfer
/// to parent). Starts PMU with an overflow threshold on itself and burns
/// events until the overflow fires. Per §2.14.14 the kernel must kill
/// the process with CrashReason.pmu_overflow.
///
/// Setup failure signalling (§2.14.14 parent-test robustness): if
/// `pmu_info` fails, no event is supported, or `pmu_start` returns
/// non-zero, we execute `ud2` so the kernel kills the process with
/// CrashReason.illegal_instruction. The parent test can then distinguish
/// "setup failed" from "overflow kill worked". Similarly, if the work
/// loop completes without being faulted (kernel regression — overflow
/// never delivered), the final `ud2` gives the parent a clear
/// illegal_instruction signal rather than leaving it to time out.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK) {
        lib.fault.illegalInstruction();
        unreachable;
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        lib.fault.illegalInstruction();
        unreachable;
    };

    const self_thread: u64 = @bitCast(syscall.thread_self());
    var cfg = syscall.PmuCounterConfig{
        .event = evt,
        .has_threshold = true,
        .overflow_threshold = 1024,
    };
    const start_rc = syscall.pmu_start(self_thread, @intFromPtr(&cfg), 1);
    if (start_rc != syscall.E_OK) {
        lib.fault.illegalInstruction();
    }

    while (true) {
        switch (@import("builtin").cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => {},
        }
    }
}
