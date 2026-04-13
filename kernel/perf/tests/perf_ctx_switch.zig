const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

/// Context switch benchmark. Isolates the scheduler's switchTo path
/// from IPC/futex/syscall entry costs by using pure thread_yield between
/// two same-priority threads on the same core.
///
/// Setup:
///   - parent pinned to core 0 at NORMAL
///   - worker thread_create'd → starts on caller's core (core 0) at NORMAL
///   - both call thread_yield in a tight loop
///
/// One iteration = one parent yield. The parent yield enqueues parent at
/// the ready-queue tail and picks the worker from the head; the worker
/// then yields, enqueues itself, picks the parent. So one iteration
/// covers exactly two context switches. Divide the reported median by 2
/// for the per-switch cost.
///
/// NOTE: this test stays at NORMAL priority (not REALTIME) because
/// `enqueueOnCore`'s preempt-IPI gate is `newpri > curpri` (strict);
/// a REALTIME parent would starve a NORMAL worker since yield doesn't
/// downgrade priority. The resulting cycle counts include timer-tick
/// jitter but are still useful as relative numbers.
pub fn main(_: u64) void {
    // Drop the default .pinned priority so we can set_affinity.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);

    const ITERATIONS: u32 = 10000;
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] ctx_switch SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    const worker_rc = syscall.thread_create(&workerLoop, 0, 4);
    if (worker_rc < 0) {
        syscall.write("[PERF] ctx_switch SKIP thread_create failed\n");
        syscall.shutdown();
    }
    const worker_h: u64 = @bitCast(worker_rc);

    // Warmup so the worker is actually scheduled before we start timing.
    var w: u32 = 0;
    while (w < 1000) : (w += 1) syscall.thread_yield();

    var i: u32 = 0;
    while (i < ITERATIONS) : (i += 1) {
        const t0 = bench.rdtscp();
        syscall.thread_yield();
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
    }

    const result = bench.computeStats(buf, ITERATIONS);
    bench.report("ctx_switch_yield_pair", result);

    // Per-switch estimate (one iteration = 2 switches).
    syscall.write("[PERF] ctx_switch_yield_pair per_switch_median=");
    printDec(result.median / 2);
    syscall.write(" cycles\n");

    _ = syscall.thread_kill(worker_h);
    syscall.shutdown();
}

fn workerLoop() void {
    while (true) syscall.thread_yield();
}

fn printDec(v: u64) void {
    lib.testing.printDec(v);
}
