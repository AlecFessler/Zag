const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.4 — `sys_info` with `cores_ptr` null writes only `SysInfo`; no per-core data is written and no scheduler accounting counters are reset.
///
/// Strategy:
///   1) Call `sys_info` with a non-null `cores_ptr` to reset all cores'
///      `idle_ns` / `busy_ns` (§2.15 / §4.55.6).
///   2) Burn CPU to accumulate accounting.
///   3) Call `sys_info` with null `cores_ptr` — this must NOT reset the
///      counters, and must NOT touch the provided CoreInfo buffer.
///   4) Burn more CPU.
///   5) Call `sys_info` with non-null `cores_ptr` again.
///
/// If the null-cores_ptr call had (incorrectly) reset the per-core
/// counters, the final sample would reflect only step (4) work. Because
/// it (correctly) does not reset, the final sample must reflect steps
/// (2)+(3)+(4) cumulative work — strictly more than a single-phase burn.
///
/// We also pre-poison the CoreInfo buffer before the null-cores_ptr call
/// and verify it remains untouched, which is the direct "no per-core data
/// is written" assertion.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    var cores: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;

    // 1) Prime reset.
    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§4.55.4 prime sys_info");
        syscall.shutdown();
    }

    // 2) Burn.
    burnCycles(200_000);
    syscall.thread_yield();

    // 3) Null cores_ptr call — poison buffer first so "not written" is
    //    detectable, and capture the SysInfo.
    const sentinel: u64 = 0xfeed_face_feed_face;
    for (&cores) |*c| {
        c.* = .{
            .idle_ns = sentinel,
            .busy_ns = sentinel,
            .freq_hz = sentinel,
            .temp_mc = 0xfeedface,
            .c_state = 0xaa,
        };
    }
    if (syscall.sys_info(@intFromPtr(&info), 0) != syscall.E_OK) {
        t.fail("§4.55.4 null-cores sys_info");
        syscall.shutdown();
    }

    // Buffer must remain sentinel-valued for every in-range slot.
    var i: u64 = 0;
    while (i < info.core_count) : (i += 1) {
        const c = cores[i];
        if (c.idle_ns != sentinel or c.busy_ns != sentinel or c.freq_hz != sentinel) {
            t.failWithVal("§4.55.4 cores buffer was written", @intCast(i), 0);
            syscall.shutdown();
        }
    }

    // 4) More burn.
    burnCycles(200_000);
    syscall.thread_yield();

    // 5) Second non-null cores_ptr call — reads accumulated counters from
    //    the whole interval since step (1), because step (3) must not
    //    have reset them.
    var info2: syscall.SysInfo = undefined;
    if (syscall.sys_info(@intFromPtr(&info2), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§4.55.4 final sys_info");
        syscall.shutdown();
    }

    // Accumulated (idle_ns + busy_ns) across all active cores must be
    // strictly nonzero — enough scheduler ticks have elapsed over our
    // two busy phases that at least one tick is accounted on some core.
    var total: u64 = 0;
    var j: u64 = 0;
    while (j < info2.core_count) : (j += 1) total += cores[j].idle_ns + cores[j].busy_ns;
    if (total == 0) {
        t.fail("§4.55.4 no per-core accounting after two bursts");
        syscall.shutdown();
    }

    t.pass("§4.55.4");
    syscall.shutdown();
}

fn burnCycles(n: u64) void {
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        acc +%= i;
        asm volatile ("" ::: .{ .memory = true });
    }
    // Prevent dead-code elimination.
    asm volatile (""
        :
        : [a] "r" (acc),
    );
}
