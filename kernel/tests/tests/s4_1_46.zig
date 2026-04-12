const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

// Fixed-size workload — one iteration is a known primitive (wrapping
// add). A buggy save/restore would either zero out A's accumulated
// counter values or clobber them with B's work, producing a ratio far
// from 1 between the solo and contended runs.
const WORKLOAD_ITERS: u64 = 200_000;

var a_ready: u64 align(8) = 0;
var b_ready: u64 align(8) = 0;
var a_start: u64 align(8) = 0;
var a_done: u64 align(8) = 0;
var b_stop: u64 align(8) = 0;

fn threadA() void {
    // §2.4.23 allows only one pinned owner per core, so this test must
    // use set_affinity (not PRIORITY_PINNED) to force same-core contention
    // with threadB. A PRIORITY_PINNED pair would silently fail with
    // E_BUSY on the second thread and run it elsewhere.
    const aff = syscall.set_affinity(0b1);
    if (aff != syscall.E_OK) {
        @atomicStore(u64, &a_ready, 0xffff_ffff_ffff_ffff, .seq_cst);
        return;
    }
    @atomicStore(u64, &a_ready, 1, .seq_cst);
    // Wait for parent to arm each phase.
    while (true) {
        while (@atomicLoad(u64, &a_start, .seq_cst) == 0) syscall.thread_yield();
        if (@atomicLoad(u64, &a_start, .seq_cst) == 2) break;

        var acc: u64 = 0;
        var i: u64 = 0;
        while (i < WORKLOAD_ITERS) : (i += 1) {
            acc +%= i;
            // Yield periodically so B actually gets to run when present,
            // forcing context switches into and out of A on the same core.
            if ((i & 0x3ff) == 0) syscall.thread_yield();
        }
        // Prevent the loop from being optimized out.
        @atomicStore(u64, &a_done, acc | 1, .seq_cst);

        @atomicStore(u64, &a_start, 0, .seq_cst);
    }
}

fn threadB() void {
    const aff = syscall.set_affinity(0b1);
    if (aff != syscall.E_OK) {
        @atomicStore(u64, &b_ready, 0xffff_ffff_ffff_ffff, .seq_cst);
        return;
    }
    @atomicStore(u64, &b_ready, 1, .seq_cst);
    var acc: u64 = 0;
    while (@atomicLoad(u64, &b_stop, .seq_cst) == 0) {
        acc +%= 1;
        if ((acc & 0xff) == 0) syscall.thread_yield();
    }
}

/// §4.1.46 — PMU counters on a thread are preserved across context switches: when the thread is descheduled the current counter values are saved, and when it is redispatched they are restored.
///
/// Strategy: both A and B are pinned to core 0 (same-core) so that when
/// B is running it forces context switches off of A and back. We run A
/// through a deterministic fixed-count workload twice:
///   (1) solo — B not yet started — record counter C_solo,
///   (2) contended — B is spinning+yielding on the same core — record C_cont.
///
/// If the kernel correctly saves/restores A's PMU state, C_cont should
/// reflect only A's own work and be within a 4x band of C_solo — a
/// deliberately wide tolerance chosen for QEMU's noisy scheduling. A
/// broken save/restore leaves C_cont either near zero (counters zeroed
/// on restore) or polluted by B's work (counters not swapped on context
/// switch) — both fall well outside the 4x bound.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§4.1.46");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        t.pass("§4.1.46");
        syscall.shutdown();
    };

    // Pin the parent somewhere other than core 0 if possible so that A and
    // B are the only things competing on core 0 (on 1-core QEMU this is a
    // no-op since there's only one core). This is best-effort.
    _ = syscall.set_affinity(~@as(u64, 0b1));

    const a_i = syscall.thread_create(&threadA, 0, 4);
    if (a_i <= 0) {
        t.fail("§4.1.46 thread_create A");
        syscall.shutdown();
    }
    const a_h: u64 = @bitCast(a_i);

    while (@atomicLoad(u64, &a_ready, .seq_cst) == 0) syscall.thread_yield();
    if (@atomicLoad(u64, &a_ready, .seq_cst) == 0xffff_ffff_ffff_ffff) {
        t.fail("§4.1.46 threadA set_affinity");
        _ = syscall.thread_kill(a_h);
        syscall.shutdown();
    }

    // Start PMU counting the first supported event on thread A only.
    var cfg = syscall.PmuCounterConfig{
        .event = evt,
        .has_threshold = false,
        .overflow_threshold = 0,
    };
    if (syscall.pmu_start(a_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§4.1.46 pmu_start A");
        _ = syscall.thread_kill(a_h);
        syscall.shutdown();
    }

    // --- Phase 1: solo run of A's workload ---
    @atomicStore(u64, &a_done, 0, .seq_cst);
    @atomicStore(u64, &a_start, 1, .seq_cst);
    while (@atomicLoad(u64, &a_done, .seq_cst) == 0) syscall.thread_yield();

    _ = syscall.thread_suspend(a_h);
    var s_solo: syscall.PmuSample = undefined;
    if (syscall.pmu_read(a_h, @intFromPtr(&s_solo)) != syscall.E_OK) {
        t.fail("§4.1.46 pmu_read solo");
        _ = syscall.thread_kill(a_h);
        syscall.shutdown();
    }
    _ = syscall.thread_resume(a_h);

    // --- Phase 2: contended run with B pinned to the same core ---
    const b_i = syscall.thread_create(&threadB, 0, 4);
    if (b_i <= 0) {
        t.fail("§4.1.46 thread_create B");
        _ = syscall.thread_kill(a_h);
        syscall.shutdown();
    }
    const b_h: u64 = @bitCast(b_i);
    while (@atomicLoad(u64, &b_ready, .seq_cst) == 0) syscall.thread_yield();
    if (@atomicLoad(u64, &b_ready, .seq_cst) == 0xffff_ffff_ffff_ffff) {
        t.fail("§4.1.46 threadB set_affinity");
        _ = syscall.thread_kill(a_h);
        _ = syscall.thread_kill(b_h);
        syscall.shutdown();
    }

    @atomicStore(u64, &a_done, 0, .seq_cst);
    @atomicStore(u64, &a_start, 1, .seq_cst);
    while (@atomicLoad(u64, &a_done, .seq_cst) == 0) syscall.thread_yield();

    _ = syscall.thread_suspend(a_h);
    var s_cont: syscall.PmuSample = undefined;
    if (syscall.pmu_read(a_h, @intFromPtr(&s_cont)) != syscall.E_OK) {
        t.fail("§4.1.46 pmu_read contended");
        @atomicStore(u64, &b_stop, 1, .seq_cst);
        _ = syscall.thread_kill(a_h);
        _ = syscall.thread_kill(b_h);
        syscall.shutdown();
    }

    // Contended delta — counters are cumulative since pmu_start, so we
    // need (cont - solo) as the instruction count attributed to the
    // second workload. Solo workload is just s_solo.counters[0].
    const c_solo = s_solo.counters[0];
    const c_cont_delta = s_cont.counters[0] -% s_solo.counters[0];

    // Preservation check: c_cont_delta should be within a 2x band of
    // c_solo — broken save/restore either leaves it near zero or
    // inflates it hugely with B's work.
    const ok_nonzero = c_solo > 0 and c_cont_delta > 0;
    const within_band = c_cont_delta >= c_solo / 4 and c_cont_delta <= c_solo * 4;

    @atomicStore(u64, &b_stop, 1, .seq_cst);
    @atomicStore(u64, &a_start, 2, .seq_cst);

    if (ok_nonzero and within_band) {
        t.pass("§4.1.46");
    } else {
        t.failWithVal("§4.1.46 counters not preserved", @bitCast(c_solo), @bitCast(c_cont_delta));
    }

    _ = syscall.pmu_stop(a_h);
    _ = syscall.thread_kill(a_h);
    _ = syscall.thread_kill(b_h);
    syscall.shutdown();
}
