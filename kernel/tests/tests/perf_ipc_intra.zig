const children = @import("embedded_children");
const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

const ITERATIONS: u32 = 5000;

/// Measures IPC round-trip between two child processes.
/// Root service spawns an echo server and a caller child, caps-transfers
/// the server handle to the caller, and the caller measures ipc_call
/// round-trip latency. Two variants: same-core and cross-core.
///
/// The caller child reports results back via IPC to the root service
/// which emits [PERF] output.
pub fn main(_: u64) void {
    // Spawn echo server
    const server_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_ipc_echo.ptr),
        children.child_perf_ipc_echo.len,
        (perms.ProcessRights{}).bits(),
    );
    if (server_rc < 0) {
        syscall.write("[PERF] ipc SKIP server proc_create failed\n");
        syscall.shutdown();
    }
    const server_handle: u64 = @bitCast(server_rc);

    // Cap-transfer server handle to caller so caller can ipc_call it directly
    // For now, simpler approach: root service does the IPC measurement itself
    // against the server child, and we control our own affinity.

    // --- Cross-core variant (parent core 0, server core 1) ---
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    // Warmup
    var w: u32 = 0;
    while (w < 100) {
        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(server_handle, &.{0x42}, &reply);
        w += 1;
    }

    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] ipc SKIP alloc failed\n");
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var i: u32 = 0;
    while (i < ITERATIONS) {
        var reply: syscall.IpcMessage = .{};
        const t0 = bench.rdtscp();
        _ = syscall.ipc_call(server_handle, &.{0x42}, &reply);
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    const cross_result = bench.computeStats(buf, ITERATIONS);
    bench.report("ipc_cross_core", cross_result);

    // --- Same-core variant (both on core 0) ---
    // Kill the first server (pinned to core 1) and spawn a new one
    _ = syscall.revoke_perm(server_handle);

    // Spawn a second echo server — this one will pin to core 0
    // since child_perf_ipc_echo pins to core 1, we need a variant
    // that pins to core 0. Since we can't change the child at runtime,
    // we'll just pin ourselves to core 1 to match the child.
    const server2_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_ipc_echo.ptr),
        children.child_perf_ipc_echo.len,
        (perms.ProcessRights{}).bits(),
    );
    if (server2_rc < 0) {
        syscall.shutdown();
    }
    const server2_handle: u64 = @bitCast(server2_rc);

    // Pin ourselves to core 1 (same as child) for same-core IPC
    _ = syscall.set_affinity(2);

    // Warmup
    w = 0;
    while (w < 100) {
        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(server2_handle, &.{0x42}, &reply);
        w += 1;
    }

    i = 0;
    while (i < ITERATIONS) {
        var reply: syscall.IpcMessage = .{};
        const t0 = bench.rdtscp();
        _ = syscall.ipc_call(server2_handle, &.{0x42}, &reply);
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    const same_result = bench.computeStats(buf, ITERATIONS);
    bench.report("ipc_same_core", same_result);

    _ = syscall.revoke_perm(server2_handle);
    syscall.shutdown();
}
