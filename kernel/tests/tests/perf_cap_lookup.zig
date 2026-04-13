const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;
const t = lib.testing;

const ITERATIONS: u32 = 5000;

/// Measures capability table lookup overhead.
/// Compares ipc_send to a valid handle (fast path, handle found but
/// no receiver) vs ipc_send to a bogus handle (E_BADHANDLE).
/// The difference isolates capability table scan cost.
pub fn main(_: u64) void {
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] cap_lookup SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    // --- Valid handle path ---
    const self_handle: u64 = @bitCast(syscall.thread_self());
    var i: u32 = 0;

    var w: u32 = 0;
    while (w < 100) {
        _ = syscall.ipc_send(self_handle, &.{0x42});
        w += 1;
    }

    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        _ = syscall.ipc_send(self_handle, &.{0x42});
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    const valid_result = bench.computeStats(buf, ITERATIONS);
    bench.report("cap_lookup_valid", valid_result);

    // --- Invalid handle path (reuse same buffer) ---
    const bogus_handle: u64 = t.BOGUS_HANDLE;
    i = 0;

    w = 0;
    while (w < 100) {
        _ = syscall.ipc_send(bogus_handle, &.{0x42});
        w += 1;
    }

    while (i < ITERATIONS) {
        const t0 = bench.rdtscp();
        _ = syscall.ipc_send(bogus_handle, &.{0x42});
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    const invalid_result = bench.computeStats(buf, ITERATIONS);
    bench.report("cap_lookup_invalid", invalid_result);

    syscall.shutdown();
}
