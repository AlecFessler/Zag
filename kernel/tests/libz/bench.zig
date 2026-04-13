const syscall = @import("syscall.zig");
const t = @import("test.zig");

// --- TSC ---

pub inline fn rdtscp() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtscp"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        :
        : .{ .rcx = true, .memory = true }
    );
    return (@as(u64, hi) << 32) | lo;
}

// --- Configuration ---

pub const BenchConfig = struct {
    name: []const u8,
    warmup: u32 = 1000,
    iterations: u32 = 10000,
    pmu_events: []const syscall.PmuEvent = &.{},
};

pub const BenchResult = struct {
    min: u64,
    max: u64,
    mean: u64,
    median: u64,
    p99: u64,
    stddev: u64,
    iterations: u32,
};

// --- Core benchmark runner ---

/// Runs a benchmark: pins to core 0 at REALTIME priority, warms up,
/// measures `iterations` invocations of `body`, computes statistics,
/// and emits [PERF] lines to serial.
///
/// If `config.pmu_events` is non-empty, PMU counters run across the
/// entire measurement loop and per-op averages are reported.
///
/// The sample buffer is allocated via `mem_reserve` (demand-paged)
/// to avoid stack overflow.
pub fn runBench(config: BenchConfig, comptime body: fn () void) BenchResult {
    // Pin to core 0, raise priority to minimize jitter.
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    // Allocate sample buffer via mem_reserve (demand-paged)
    const buf_bytes = @as(u64, config.iterations) * @sizeOf(u64);
    const buf_pages = (buf_bytes + syscall.PAGE4K - 1) / syscall.PAGE4K;
    const reserve_result = syscall.mem_reserve(0, buf_pages * syscall.PAGE4K, 0x3);
    if (reserve_result.val < 0) {
        syscall.write("[PERF] ");
        syscall.write(config.name);
        syscall.write(" SKIP mem_reserve failed\n");
        return .{ .min = 0, .max = 0, .mean = 0, .median = 0, .p99 = 0, .stddev = 0, .iterations = 0 };
    }
    const buf_ptr: [*]u64 = @ptrFromInt(reserve_result.val2);
    const buf = buf_ptr[0..config.iterations];

    // Warmup
    var w: u32 = 0;
    while (w < config.warmup) {
        body();
        w += 1;
    }

    // Optional PMU setup
    const self_thread: u64 = @bitCast(syscall.thread_self());
    var pmu_started = false;
    var pmu_configs: [syscall.PMU_MAX_COUNTERS]syscall.PmuCounterConfig = undefined;

    if (config.pmu_events.len > 0) {
        for (config.pmu_events, 0..) |evt, i| {
            pmu_configs[i] = .{
                .event = evt,
                .has_threshold = false,
                .overflow_threshold = 0,
            };
        }
        if (syscall.pmu_start(self_thread, @intFromPtr(&pmu_configs), config.pmu_events.len) == syscall.E_OK) {
            pmu_started = true;
        }
    }

    // Measurement loop
    var i: u32 = 0;
    while (i < config.iterations) {
        const t0 = rdtscp();
        body();
        const t1 = rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    // PMU readout
    var pmu_sample: syscall.PmuSample = .{};
    if (pmu_started) {
        _ = syscall.pmu_read(self_thread, @intFromPtr(&pmu_sample));
        _ = syscall.pmu_stop(self_thread);
    }

    // Compute stats
    const result = computeStats(buf[0..config.iterations], config.iterations);

    // Report
    report(config.name, result);
    if (pmu_started) {
        reportPmu(config.name, pmu_sample, config.pmu_events, config.iterations);
    }

    return result;
}

/// Allocate a demand-paged buffer for sample storage.
/// Returns null if allocation fails.
pub fn allocBuf(count: u32) ?[*]u64 {
    const buf_bytes = @as(u64, count) * @sizeOf(u64);
    const buf_pages = (buf_bytes + syscall.PAGE4K - 1) / syscall.PAGE4K;
    const result = syscall.mem_reserve(0, buf_pages * syscall.PAGE4K, 0x3);
    if (result.val < 0) return null;
    return @ptrFromInt(result.val2);
}

// --- Statistics ---

pub fn computeStats(buf: []u64, iterations: u32) BenchResult {
    insertionSort(buf);

    const n: u64 = iterations;
    var sum: u64 = 0;
    var sum_sq: u128 = 0;

    for (buf[0..iterations]) |v| {
        sum += v;
        sum_sq += @as(u128, v) * @as(u128, v);
    }

    const mean = sum / n;
    const variance = @as(u64, @truncate(sum_sq / n -% @as(u128, mean) * @as(u128, mean)));
    const stddev = isqrt(variance);

    const p99_idx = (n * 99) / 100;

    return .{
        .min = buf[0],
        .max = buf[iterations - 1],
        .mean = mean,
        .median = buf[iterations / 2],
        .p99 = buf[@intCast(p99_idx)],
        .stddev = stddev,
        .iterations = iterations,
    };
}

fn insertionSort(buf: []u64) void {
    if (buf.len <= 1) return;
    var i: usize = 1;
    while (i < buf.len) {
        const key = buf[i];
        var j: usize = i;
        while (j > 0 and buf[j - 1] > key) {
            buf[j] = buf[j - 1];
            j -= 1;
        }
        buf[j] = key;
        i += 1;
    }
}

fn isqrt(n: u64) u64 {
    if (n == 0) return 0;
    var x = n;
    var y = (x + 1) / 2;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }
    return x;
}

// --- Reporting ---

pub fn report(name: []const u8, result: BenchResult) void {
    perfLine(name, "min", result.min, "cycles");
    perfLine(name, "median", result.median, "cycles");
    perfLine(name, "mean", result.mean, "cycles");
    perfLine(name, "p99", result.p99, "cycles");
    perfLine(name, "max", result.max, "cycles");
    perfLine(name, "stddev", result.stddev, "cycles");
    perfLineU32(name, "iterations", result.iterations);
}

pub fn reportPmu(
    name: []const u8,
    sample: syscall.PmuSample,
    events: []const syscall.PmuEvent,
    iterations: u32,
) void {
    const n: u64 = iterations;
    for (events, 0..) |evt, i| {
        const total = sample.counters[i];
        const per_op = total / n;
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" ");
        syscall.write(pmuEventName(evt));
        syscall.write("_per_op=");
        t.printDec(per_op);
        syscall.write("\n");
    }
}

fn perfLine(name: []const u8, metric: []const u8, value: u64, unit: []const u8) void {
    syscall.write("[PERF] ");
    syscall.write(name);
    syscall.write(" ");
    syscall.write(metric);
    syscall.write("=");
    t.printDec(value);
    syscall.write(" ");
    syscall.write(unit);
    syscall.write("\n");
}

fn perfLineU32(name: []const u8, metric: []const u8, value: u32) void {
    syscall.write("[PERF] ");
    syscall.write(name);
    syscall.write(" ");
    syscall.write(metric);
    syscall.write("=");
    t.printDec(value);
    syscall.write("\n");
}

fn pmuEventName(evt: syscall.PmuEvent) []const u8 {
    return switch (evt) {
        .cycles => "cycles",
        .instructions => "instructions",
        .cache_references => "cache_references",
        .cache_misses => "cache_misses",
        .branch_instructions => "branch_instructions",
        .branch_misses => "branch_misses",
        .bus_cycles => "bus_cycles",
        .stalled_cycles_frontend => "stalled_frontend",
        .stalled_cycles_backend => "stalled_backend",
        _ => "unknown",
    };
}
