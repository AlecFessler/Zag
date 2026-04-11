const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var a_ready: u64 align(8) = 0;
var b_ready: u64 align(8) = 0;
var a_stop: u64 align(8) = 0;
var b_stop: u64 align(8) = 0;

fn threadA() void {
    @atomicStore(u64, &a_ready, 1, .seq_cst);
    var acc: u64 = 0;
    while (@atomicLoad(u64, &a_stop, .seq_cst) == 0) {
        acc +%= 1;
        if ((acc & 0xffff) == 0) syscall.thread_yield();
    }
}

fn threadB() void {
    @atomicStore(u64, &b_ready, 1, .seq_cst);
    var acc: u64 = 0;
    while (@atomicLoad(u64, &b_stop, .seq_cst) == 0) {
        acc +%= 1;
        if ((acc & 0xffff) == 0) syscall.thread_yield();
    }
}

/// §2.14.10 — PMU counters on a thread are preserved across context switches: when the thread is descheduled the current counter values are saved, and when it is redispatched they are restored.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or info.num_counters == 0) {
        t.pass("§2.14.10");
        syscall.shutdown();
    }

    const a_i = syscall.thread_create(&threadA, 0, 4);
    const b_i = syscall.thread_create(&threadB, 0, 4);
    if (a_i <= 0 or b_i <= 0) {
        t.fail("§2.14.10 thread_create");
        syscall.shutdown();
    }
    const a_h: u64 = @bitCast(a_i);
    const b_h: u64 = @bitCast(b_i);

    while (@atomicLoad(u64, &a_ready, .seq_cst) == 0 or
        @atomicLoad(u64, &b_ready, .seq_cst) == 0) syscall.thread_yield();

    // Start PMU counting instructions on thread A only.
    var cfg = syscall.PmuCounterConfig{
        .event = .instructions,
        .has_threshold = false,
        .overflow_threshold = 0,
    };
    if (syscall.pmu_start(a_h, @intFromPtr(&cfg), 1) != syscall.E_OK) {
        t.fail("§2.14.10 pmu_start A");
        syscall.shutdown();
    }

    // Let A and B alternate — context switches force save/restore of A's
    // counters. If A's counters were clobbered by B's intervening work
    // the counts would be zero-ish or non-monotonic.
    for (0..500) |_| syscall.thread_yield();

    // Suspend A and take a first snapshot.
    _ = syscall.thread_suspend(a_h);
    var s1: syscall.PmuSample = undefined;
    if (syscall.pmu_read(a_h, @intFromPtr(&s1)) != syscall.E_OK) {
        t.fail("§2.14.10 pmu_read 1");
        syscall.shutdown();
    }
    _ = syscall.thread_resume(a_h);

    for (0..500) |_| syscall.thread_yield();

    _ = syscall.thread_suspend(a_h);
    var s2: syscall.PmuSample = undefined;
    if (syscall.pmu_read(a_h, @intFromPtr(&s2)) != syscall.E_OK) {
        t.fail("§2.14.10 pmu_read 2");
        syscall.shutdown();
    }

    // Snapshot 2 must be non-zero AND >= snapshot 1, and strictly greater
    // if A made forward progress between the two reads. A clobbered
    // counter would either be reset to zero or randomly lower.
    if (s2.counters[0] < s1.counters[0] or s2.counters[0] == 0) {
        t.fail("§2.14.10 counters not preserved across context switch");
        @atomicStore(u64, &a_stop, 1, .seq_cst);
        @atomicStore(u64, &b_stop, 1, .seq_cst);
        _ = syscall.thread_kill(a_h);
        _ = syscall.thread_kill(b_h);
        syscall.shutdown();
    }

    t.pass("§2.14.10");
    @atomicStore(u64, &a_stop, 1, .seq_cst);
    @atomicStore(u64, &b_stop, 1, .seq_cst);
    _ = syscall.pmu_stop(a_h);
    _ = syscall.thread_kill(a_h);
    _ = syscall.thread_kill(b_h);
    syscall.shutdown();
}
