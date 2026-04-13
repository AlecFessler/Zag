const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;

const ITERATIONS: u32 = 1000;

/// Measures memory reservation and page fault costs.
/// 1. mem_reserve for a single 4K page (allocation cost)
/// 2. First write to the page (demand paging / page fault cost)
pub fn main(_: u64) void {
    // Drop root's default .pinned priority before set_affinity; see
    // kernel/syscall/thread.zig:98 (set_affinity is E_BUSY while pinned).
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] mem_reserve SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    // --- mem_reserve benchmark ---
    // Warmup (revoke handles to avoid exhausting 128-handle cap)
    var w: u32 = 0;
    while (w < 50) {
        const result = syscall.mem_reserve(0, syscall.PAGE4K, 0x7);
        if (result.val >= 0) {
            _ = syscall.revoke_perm(@intCast(result.val));
        }
        w += 1;
    }

    var i: u32 = 0;
    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        const result = syscall.mem_reserve(0, syscall.PAGE4K, 0x7);
        const t1 = bench.rdtscp();
        if (result.val < 0) break;
        buf[i] = t1 -% t0;
        // Free the handle so we don't exhaust the cap table
        _ = syscall.revoke_perm(@intCast(result.val));
        i += 1;
    }

    if (i > 0) {
        const reserve_result = bench.computeStats(buf[0..i], @intCast(i));
        bench.report("mem_reserve", reserve_result);
    }

    // --- Page fault benchmark ---
    // Reserve pages (keep handles alive — we need the pages mapped).
    // Limited to 100 iterations to stay within 128-handle cap
    // (2 handles used by allocBuf above).
    const FAULT_ITERS: u32 = 100;
    const addr_ptr = bench.allocBuf(FAULT_ITERS) orelse {
        syscall.write("[PERF] page_fault SKIP alloc failed\n");
        syscall.shutdown();
    };
    const addrs = addr_ptr[0..FAULT_ITERS];

    var j: u32 = 0;
    while (j < FAULT_ITERS) {
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
