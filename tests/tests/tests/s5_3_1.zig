const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.3.1 — `SysInfo.core_count` is the number of active CPU cores the kernel scheduled on at boot.
///
/// Call `sys_info` twice with a delay in between and verify `core_count` is:
///   1) non-zero (the kernel always schedules on at least the BSP),
///   2) bounded by the §5 limit `MAX_CPU_CORES = 64`, and
///   3) stable across calls (§5.3.1 explicitly calls it a static property of
///      a given boot). A kernel regression that recomputed `core_count` per
///      call from transient state would fail the stability check.
pub fn main(_: u64) void {
    var info_a: syscall.SysInfo = undefined;
    var info_b: syscall.SysInfo = undefined;

    // Pre-poison so a kernel that fails to write the field surfaces as
    // nonsense rather than a lucky zero.
    const a_bytes: [*]u8 = @ptrCast(&info_a);
    const b_bytes: [*]u8 = @ptrCast(&info_b);
    for (0..@sizeOf(syscall.SysInfo)) |i| a_bytes[i] = 0xff;
    for (0..@sizeOf(syscall.SysInfo)) |i| b_bytes[i] = 0xff;

    const rc_a = syscall.sys_info(@intFromPtr(&info_a), 0);
    if (rc_a != syscall.E_OK) {
        t.failWithVal("§5.3.1 first call", syscall.E_OK, rc_a);
        syscall.shutdown();
    }

    // Churn the scheduler a bit between calls. A regression that let
    // core_count drift with scheduler state would catch this.
    var i: u64 = 0;
    while (i < 64) : (i += 1) syscall.thread_yield();

    const rc_b = syscall.sys_info(@intFromPtr(&info_b), 0);
    if (rc_b != syscall.E_OK) {
        t.failWithVal("§5.3.1 second call", syscall.E_OK, rc_b);
        syscall.shutdown();
    }

    if (info_a.core_count == 0) {
        t.fail("§5.3.1 core_count == 0");
        syscall.shutdown();
    }
    if (info_a.core_count > syscall.MAX_CPU_CORES) {
        t.failWithVal(
            "§5.3.1 core_count > MAX_CPU_CORES",
            @intCast(syscall.MAX_CPU_CORES),
            @intCast(info_a.core_count),
        );
        syscall.shutdown();
    }
    if (info_a.core_count != info_b.core_count) {
        t.failWithVal(
            "§5.3.1 core_count not stable",
            @intCast(info_a.core_count),
            @intCast(info_b.core_count),
        );
        syscall.shutdown();
    }

    t.pass("§5.3.1");
    syscall.shutdown();
}
