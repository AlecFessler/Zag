const children = @import("embedded_children");
const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

const ITERATIONS: u32 = 5000;

/// Measures IPC round-trip between two separate processes.
/// Parent calls child echo server, measures full call+reply latency.
/// Shows isolation overhead vs intra-process IPC.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: i64 = syscall.proc_create(
        @intFromPtr(children.child_perf_ipc_echo.ptr),
        children.child_perf_ipc_echo.len,
        child_rights.bits(),
    );
    if (ch < 0) {
        syscall.write("[PERF] ipc_cross SKIP proc_create failed\n");
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(ch);

    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    // Warmup
    var w: u32 = 0;
    while (w < 100) {
        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(child_handle, &.{0x42}, &reply);
        w += 1;
    }

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] ipc_cross SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var i: u32 = 0;
    while (i < ITERATIONS) {
        var reply: syscall.IpcMessage = .{};
        const t0 = bench.rdtscp();
        _ = syscall.ipc_call(child_handle, &.{0x42}, &reply);
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    const result = bench.computeStats(buf, ITERATIONS);
    bench.report("ipc_cross", result);

    _ = syscall.revoke_perm(child_handle);
    syscall.shutdown();
}
