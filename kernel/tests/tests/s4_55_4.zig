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
/// reset `idle_ns`/`busy_ns` on a null `cores_ptr` call would wipe the
/// counters between two back-to-back reads where no other time has
/// elapsed. We exploit that:
///
///   1) Drain accounting with a non-null `sys_info` call (per §4.55.6
///      this zeroes each core's `idle_ns` / `busy_ns`). Discard the
///      values — this is the baseline.
///   2) Burn a large amount of CPU on the parent thread so many
///      scheduler ticks land, accumulating tens of ms of accounting on
///      the busy core and idle_ns on the others.
///   3) `yield` once to make sure a tick has definitely landed after
///      the burn loop.
///   4) Call `sys_info` with `cores_ptr = 0`. This is the call under
///      test — it MUST NOT reset the accounting that step (2) built up.
///   5) *Immediately* call `sys_info` with `cores_ptr` non-null and sum
///      `idle_ns + busy_ns` across cores.
///
/// There is essentially zero wall-time between steps (4) and (5) — one
/// kernel exit and one kernel entry, no yield, no burn. So:
///
///   - A correct kernel leaves the step-(2) accounting in place across
///     the null call, and step (5) captures ~tens of ms of accumulated
///     time (burst duration × core_count, minus whatever the baseline
///     drain in step 1 wrote to zero).
///   - A buggy kernel that reset on the null call would shrink the
///     step-(5) total to "time elapsed between steps (4) and (5)", which
///     is nanoseconds of syscall overhead — several orders of magnitude
///     below a millisecond.
///
/// A 1 ms total-time threshold is comfortably above kernel-entry overhead
/// and comfortably below the burst's wall-clock duration on any host
/// QEMU runs on.
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

    // Step 1: drain the per-core counters via a non-null read.
    // (Discard the drained values — this establishes a zeroed baseline
    // so step (5)'s total is bounded below by whatever the burn in
    // step (2) produces, NOT by arbitrary boot-time accumulation.)
    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§4.55.4 drain sys_info");
        syscall.shutdown();
    }

    // Step 2: burn a lot of wall-time so many scheduler ticks land and
    // fresh accounting accumulates on every core (busy_ns on this core,
    // idle_ns on the others).
    burnCycles(20_000_000);

    // Step 3: yield once to guarantee at least one scheduler tick has
    // attributed elapsed time to the running thread after the burn.
    syscall.thread_yield();

    // Step 4: the call under test. A null `cores_ptr` call MUST NOT
    // reset the per-core accounting that step (2) built up.
    if (syscall.sys_info(@intFromPtr(&info), 0) != syscall.E_OK) {
        t.fail("§4.55.4 null-cores sys_info (mid-test)");
        syscall.shutdown();
    }

    // Step 5: immediately read accounting with a non-null `cores_ptr`.
    // There is essentially zero wall-time between steps (4) and (5) —
    // one kernel exit and one kernel entry, no yield, no burn. A
    // correct kernel reports the tens of ms of accounting that step (2)
    // built up; a buggy kernel that reset on step (4) reports only the
    // tiny syscall-overhead gap between the two calls.
    if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
        t.fail("§4.55.4 post-null sys_info");
        syscall.shutdown();
    }
    var total: u64 = 0;
    var k: u64 = 0;
    while (k < info.core_count) : (k += 1) {
        total += cores[k].idle_ns + cores[k].busy_ns;
    }

    // Threshold: 50 ms of aggregate accounting. The scheduler tick is
    // 2 ms (§6, `SCHED_TIMESLICE_NS`), so a SINGLE tick landing between
    // steps (4) and (5) on a busy rig could contribute up to ~2 ms per
    // core × core_count — on a 4-core QEMU that is already ~8 ms of
    // noise from one tick, and VM-scheduling jitter can push it higher.
    // A 1 ms threshold is therefore too tight: a buggy kernel that
    // reset on the null call could still scrape above 1 ms from a
    // single stray tick attributed to idle_ns. 50 ms is comfortably
    // above that noise floor while still being an order of magnitude
    // below the tens-to-hundreds of ms of burn accounting step (2)
    // produces on any realistic host — headroom is ~10x either way.
    const MIN_TOTAL_NS: u64 = 50_000_000;
    if (total < MIN_TOTAL_NS) {
        t.failWithVal(
            "§4.55.4 null call appears to have reset accounting",
            @intCast(MIN_TOTAL_NS),
            @intCast(total),
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
