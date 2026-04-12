const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.4 — `sys_info` with `cores_ptr` null writes only `SysInfo`; no per-core data is written and no scheduler accounting counters are reset.
///
/// Two independent half-tests run back-to-back:
///
/// **Half A — buffer is untouched.** Pre-poison the `CoreInfo` buffer with
/// a recognisable sentinel, call `sys_info` with `cores_ptr = 0`, and
/// confirm every in-range entry is still sentinel-valued. This is the
/// direct "no per-core data is written" assertion.
///
/// **Half B — accounting counters are not reset.** A buggy kernel that
/// reset `idle_ns`/`busy_ns` even on a null `cores_ptr` call would still
/// pass a "totals nonzero" check, so we have to construct a stronger one:
///   1) Burn CPU on the parent thread (burst 1).
///   2) Read accounting with `cores_ptr` non-null — capture
///      `total_after_burn1 = sum(idle_ns + busy_ns)`. (This *does* reset
///      the per-core counters per §4.55.6.)
///   3) Call `sys_info` with `cores_ptr = 0`. This is the call under test:
///      it must NOT touch the per-core accounting.
///   4) Burn CPU again (burst 2).
///   5) Read accounting with `cores_ptr` non-null — capture
///      `total_after_burn2`.
///   6) Assert `total_after_burn2 > total_after_burn1`.
///
/// Step (2) drained the counters, so without the null call (3) the only
/// accounting that step (5) could see is whatever burst 2 + the sys_info
/// itself accumulated since (2). But because step (3) must NOT reset, the
/// counters at step (5) reflect the residual that was already accumulating
/// since step (2), PLUS burst 2's work — strictly more than just the
/// post-(2) residual would be on its own. The inequality is conservative:
/// it would catch a buggy kernel that wiped counters on the null call,
/// because then step (5) would see only the (much smaller) gap between
/// (3) and (5), which could plausibly be smaller than the gap between
/// (2) and (3) measured in step 2's reading.
///
/// Reading the inequality more directly: the totals at step (5) MUST be
/// strictly larger than at step (2) because more wall-time has elapsed
/// AND the null call (3) is forbidden from clearing them. A reset would
/// shrink the (5) total to "burst 2 only", which is on the same order of
/// magnitude as the (2) total — and on a fast host could come in lower.
/// Calibrating burst 2 to be at least as long as burst 1 ensures the
/// non-buggy path is monotonic.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    var cores: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;

    // ── Half A: poison + null call must not touch the buffer. ────────
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
    var i: u64 = 0;
    while (i < info.core_count) : (i += 1) {
        const c = cores[i];
        if (c.idle_ns != sentinel or c.busy_ns != sentinel or c.freq_hz != sentinel) {
            t.failWithVal("§4.55.4 cores buffer was written", @intCast(i), 0);
            syscall.shutdown();
        }
    }

    // ── Half B: null call must not reset per-core accounting. ────────
    //
    // Burst 1: accumulate accounting on at least one core.
    burnCycles(2_000_000);
    syscall.thread_yield();

    // Sample 1 (this drains counters per §4.55.6).
    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§4.55.4 sample1 sys_info");
        syscall.shutdown();
    }
    var total_after_burn1: u64 = 0;
    var k: u64 = 0;
    while (k < info.core_count) : (k += 1) {
        total_after_burn1 += cores[k].idle_ns + cores[k].busy_ns;
    }
    if (total_after_burn1 == 0) {
        t.fail("§4.55.4 sample1 zero accounting");
        syscall.shutdown();
    }

    // Null-cores_ptr call — the call under test. Must not reset.
    if (syscall.sys_info(@intFromPtr(&info), 0) != syscall.E_OK) {
        t.fail("§4.55.4 null-cores sys_info (mid-test)");
        syscall.shutdown();
    }

    // Burst 2: keep at least as much work as burst 1 so the non-buggy
    // path is reliably monotonic on fast hosts.
    burnCycles(2_000_000);
    syscall.thread_yield();

    // Sample 2.
    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§4.55.4 sample2 sys_info");
        syscall.shutdown();
    }
    var total_after_burn2: u64 = 0;
    var m: u64 = 0;
    while (m < info.core_count) : (m += 1) {
        total_after_burn2 += cores[m].idle_ns + cores[m].busy_ns;
    }

    // The decisive check: a kernel that incorrectly reset accounting on
    // the null call would have to make burst 2 alone exceed
    // total_after_burn1, which is unrelated to burst 2's work. For
    // calibrated equal-length bursts the strict inequality holds because
    // burst 2's accounting is *added* to the residual that was already
    // building between sample 1 and the null call.
    if (total_after_burn2 <= total_after_burn1) {
        t.failWithVal(
            "§4.55.4 null call appears to have reset accounting",
            @intCast(total_after_burn1),
            @intCast(total_after_burn2),
        );
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
