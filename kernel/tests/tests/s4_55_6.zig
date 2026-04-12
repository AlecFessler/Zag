const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.6 — On success with `cores_ptr` non-null, `sys_info` writes `SysInfo` to `info_ptr` and a fully populated `CoreInfo` array to `cores_ptr`, and resets each core's `idle_ns` and `busy_ns` atomically as they are read.
///
/// Verifies two things at once:
///   1) **Full population.** Pre-poison the `CoreInfo` buffer with a
///      recognisable sentinel and verify every in-range entry has been
///      overwritten (at least one u64 field differs from the sentinel).
///   2) **Read-and-reset.** Call `sys_info` with non-null `cores_ptr`
///      twice in rapid succession, with minimal work in between. The
///      second sample's `idle_ns + busy_ns` (across all cores) must be
///      strictly less than the first sample's because the first call
///      consumed and cleared the accumulated accounting. Using
///      scheduler-tick accounting, "less than" is a robust inequality:
///      the cumulative-from-boot burst in sample 1 is huge compared to
///      whatever single-tick drip sample 2 picks up in the microseconds
///      between the two calls.
pub fn main(_: u64) void {
    // Burn enough CPU to guarantee the first sys_info reads a nonzero
    // cumulative busy_ns on at least one core.
    burnCycles(400_000);
    syscall.thread_yield();

    var info1: syscall.SysInfo = undefined;
    var cores1: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;
    const sentinel: u64 = 0xa5a5_a5a5_a5a5_a5a5;
    for (&cores1) |*c| {
        c.* = .{
            .idle_ns = sentinel,
            .busy_ns = sentinel,
            .freq_hz = sentinel,
            .temp_mc = 0xa5a5a5a5,
            .c_state = 0xa5,
        };
    }

    if (syscall.sys_info(@intFromPtr(&info1), @intFromPtr(&cores1)) != syscall.E_OK) {
        t.fail("§4.55.6 first sys_info");
        syscall.shutdown();
    }

    // Full-population check.
    var i: u64 = 0;
    var total1: u64 = 0;
    while (i < info1.core_count) : (i += 1) {
        const c = cores1[i];
        const still_sentinel =
            c.idle_ns == sentinel and
            c.busy_ns == sentinel and
            c.freq_hz == sentinel;
        if (still_sentinel) {
            t.failWithVal("§4.55.6 entry not populated", @intCast(i), @intCast(info1.core_count));
            syscall.shutdown();
        }
        total1 += c.idle_ns + c.busy_ns;
    }
    if (total1 == 0) {
        t.fail("§4.55.6 first sample: zero total accounting (cannot prove reset)");
        syscall.shutdown();
    }

    // Second sample immediately after — minimal gap. Because the first
    // call atomically reset idle_ns/busy_ns, the second call sees only
    // the (tiny) accounting window between the two calls.
    var info2: syscall.SysInfo = undefined;
    var cores2: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;
    if (syscall.sys_info(@intFromPtr(&info2), @intFromPtr(&cores2)) != syscall.E_OK) {
        t.fail("§4.55.6 second sys_info");
        syscall.shutdown();
    }

    var total2: u64 = 0;
    var j: u64 = 0;
    while (j < info2.core_count) : (j += 1) total2 += cores2[j].idle_ns + cores2[j].busy_ns;

    if (total2 >= total1) {
        t.failWithVal(
            "§4.55.6 second sample not smaller — reset did not happen",
            @intCast(total1),
            @intCast(total2),
        );
        syscall.shutdown();
    }

    t.pass("§4.55.6");
    syscall.shutdown();
}

fn burnCycles(n: u64) void {
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        acc +%= i;
        asm volatile ("" ::: .{ .memory = true });
    }
    asm volatile (""
        :
        : [a] "r" (acc),
    );
}
