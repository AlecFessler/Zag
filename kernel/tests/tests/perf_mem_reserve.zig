const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

const ITERATIONS: u32 = 1000;

/// Measures memory reservation and page fault costs.
/// 1. mem_reserve for a single 4K page (allocation cost)
/// 2. First write to the page (demand paging / page fault cost)
pub fn main(_: u64) void {
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] mem_reserve SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    // Also need an array of addresses for the page fault benchmark
    const addr_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] mem_reserve SKIP alloc2 failed\n");
        syscall.shutdown();
    };
    const addrs = addr_ptr[0..ITERATIONS];

    // --- mem_reserve benchmark ---
    // Warmup
    var w: u32 = 0;
    while (w < 50) {
        _ = syscall.mem_reserve(0, syscall.PAGE4K, 0x7);
        w += 1;
    }

    var i: u32 = 0;
    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        const result = syscall.mem_reserve(0, syscall.PAGE4K, 0x7);
        const t1 = bench.rdtscp();
        if (result.val < 0) break;
        buf[i] = t1 -% t0;
        i += 1;
    }

    if (i > 0) {
        const reserve_result = bench.computeStats(buf[0..i], @intCast(i));
        bench.report("mem_reserve", reserve_result);
    }

    // --- Page fault benchmark ---
    // Pre-reserve all pages
    var j: u32 = 0;
    while (j < ITERATIONS) {
        const result = syscall.mem_reserve(0, syscall.PAGE4K, 0x7);
        if (result.val < 0) break;
        addrs[j] = result.val2;
        j += 1;
    }

    // Measure first-touch (page fault) cost
    var k: u32 = 0;
    while (k < j) {
        const ptr: *volatile u64 = @ptrFromInt(addrs[k]);
        const t0 = bench.rdtscp();
        ptr.* = 0xCAFE;
        const t1 = bench.rdtscp();
        buf[k] = t1 -% t0;
        k += 1;
    }

    if (k > 0) {
        const fault_result = bench.computeStats(buf[0..k], @intCast(k));
        bench.report("page_fault", fault_result);
    }

    syscall.shutdown();
}
