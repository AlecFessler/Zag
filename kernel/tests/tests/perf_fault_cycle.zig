const children = @import("embedded_children");
const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// Fault round-trip benchmark. Measures the debugger/tracer hot path:
///   child  → int3 → kernel fault delivery → parent fault_recv
///   parent → fault_reply(FAULT_RESUME) → kernel resumes child → repeat
///
/// This is representative of any system that steps a traced process,
/// handles asynchronous faults remotely (e.g. VMM sampling, debugger,
/// in-kernel tracer), or uses breakpoint-based instrumentation.
///
/// One iteration = one fault_recv + one fault_reply. The child is
/// executing `int3` in a tight loop so the measurement floor is two
/// process switches (child→parent→child) plus the kernel's fault
/// delivery/reply machinery.
pub fn main(_: u64) void {
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .set_affinity = true,
    };
    const ch_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_fault_int3.ptr),
        children.child_perf_fault_int3.len,
        child_rights.bits(),
    );
    if (ch_rc < 0) {
        syscall.write("[PERF] fault_cycle SKIP proc_create failed\n");
        syscall.shutdown();
    }
    const ch: u64 = @bitCast(ch_rc);

    // Round 1: cap-transfer fault_handler from child to parent.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    const ITERATIONS: u32 = 2000;
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] fault_cycle SKIP alloc failed\n");
        _ = syscall.revoke_perm(ch);
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var fault_buf: [256]u8 align(8) = undefined;

    // Warmup: drain a few faults to get both processes hot.
    var w: u32 = 0;
    while (w < 100) : (w += 1) {
        const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
        if (token < 0) break;
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_RESUME);
    }

    // Measurement loop. Time from parent's rdtscp before fault_recv
    // (parent blocked, waiting for next child fault) to rdtscp after
    // fault_reply returns (parent has handed control back to child and
    // control has come back to parent from the next fault). That's one
    // full round trip: child fault → parent handler → child resume →
    // next child fault.
    //
    // Alternative framing: time only fault_recv + fault_reply as two
    // separate intervals. But the recv-to-reply gap is dominated by
    // parent-side code (essentially zero here), so the round trip
    // captures the cycle cleanly.
    var i: u32 = 0;
    while (i < ITERATIONS) : (i += 1) {
        const t0 = bench.rdtscp();
        const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
        if (token < 0) break;
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_RESUME);
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
    }

    if (i > 0) {
        bench.report("fault_cycle_int3", bench.computeStats(buf[0..i], @intCast(i)));
    }

    _ = syscall.revoke_perm(ch);
    syscall.shutdown();
}
