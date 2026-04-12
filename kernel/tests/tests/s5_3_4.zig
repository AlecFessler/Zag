const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.3.4 — `CoreInfo` entries are indexed by core ID: entry `i` describes core `i` for `i` in `[0, core_count)`.
///
/// Drive some scheduler work, then call `sys_info` with a non-null
/// `cores_ptr` and verify every entry in `[0, core_count)` is populated with
/// a plausible value (any core that has ever run at least one tick should
/// have `idle_ns + busy_ns > 0`). The core that ran the sys_info handler is
/// guaranteed to have tick-accumulated busy_ns between `perCoreInit` and
/// the call, so *at least one* entry being populated is a hard lower bound
/// on correctness. Entries outside `[0, core_count)` must remain at their
/// pre-poisoned sentinel value — catches a kernel that overwrites entries
/// past the end of the array.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    if (syscall.sys_info(@intFromPtr(&info), 0) != syscall.E_OK) {
        t.fail("§5.3.4 initial sys_info");
        syscall.shutdown();
    }
    if (info.core_count == 0 or info.core_count > syscall.MAX_CPU_CORES) {
        t.failWithVal(
            "§5.3.4 bogus core_count",
            @intCast(syscall.MAX_CPU_CORES),
            @intCast(info.core_count),
        );
        syscall.shutdown();
    }

    var cores: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;
    const sentinel: u64 = 0xdead_beef_dead_beef;
    for (&cores) |*c| {
        c.* = .{
            .idle_ns = sentinel,
            .busy_ns = sentinel,
            .freq_hz = sentinel,
            .temp_mc = 0xdeadbeef,
            .c_state = 0xff,
        };
    }

    // Do some work so the scheduler has something to attribute.
    var spin: u64 = 0;
    while (spin < 100_000) : (spin += 1) {
        asm volatile ("" ::: .{ .memory = true });
    }
    syscall.thread_yield();

    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§5.3.4 sys_info with cores");
        syscall.shutdown();
    }

    // Every in-range entry must have been written: at minimum, none of its
    // u64 fields can be the untouched sentinel (since a correct kernel
    // stamps each field with an arch-dispatch value or a live accounting
    // read). A core that legitimately has all-zero accounting after reset
    // still has `freq_hz` stamped by `getCoreFreq` (x64: nonzero from
    // IA32_PERF_STATUS; aarch64 stub: 0 — which equals zero, not the
    // sentinel, and therefore still differs from the sentinel).
    var populated_cores: u64 = 0;
    var i: u64 = 0;
    while (i < info.core_count) : (i += 1) {
        const c = cores[i];
        const untouched =
            c.idle_ns == sentinel and
            c.busy_ns == sentinel and
            c.freq_hz == sentinel;
        if (untouched) {
            t.failWithVal("§5.3.4 entry not populated", @intCast(i), @intCast(info.core_count));
            syscall.shutdown();
        }
        if (c.idle_ns + c.busy_ns > 0) populated_cores += 1;
    }

    // At minimum the core that serviced the syscall must have accumulated
    // some busy_ns between boot and now. If *no* core has nonzero
    // accounting the kernel is not driving the idle/busy hook at all.
    if (populated_cores == 0) {
        t.fail("§5.3.4 no core has nonzero accounting");
        syscall.shutdown();
    }

    // Entries outside [0, core_count) must still hold the sentinel — the
    // kernel must not overshoot the caller's buffer.
    var j: u64 = info.core_count;
    while (j < syscall.MAX_CPU_CORES) : (j += 1) {
        const c = cores[j];
        if (c.idle_ns != sentinel or c.busy_ns != sentinel or c.freq_hz != sentinel) {
            t.failWithVal("§5.3.4 out-of-range entry overwritten", @intCast(j), @intCast(info.core_count));
            syscall.shutdown();
        }
    }

    t.pass("§5.3.4");
    syscall.shutdown();
}
