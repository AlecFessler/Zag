const lib = @import("lib");

const bench = lib.bench;
const syscall = lib.syscall;
const t = lib.testing;

/// Measures IPC round-trip between two threads in the same process.
/// Thread A does ipc_call, thread B does ipc_recv + ipc_reply.
/// Reports both same-core and cross-core variants.
pub fn main(_: u64) void {
    // Cross-core variant first (A=core 0, B=core 1)
    runVariant("ipc_intra_cross_core", 1, 2);

    // Same-core variant (both on core 0)
    runVariant("ipc_intra_same_core", 1, 1);

    syscall.shutdown();
}

const ITERATIONS: u32 = 5000;

fn runVariant(name: []const u8, a_mask: u64, b_mask: u64) void {
    var shared = Shared{};
    shared.b_affinity = b_mask;

    const rc = syscall.thread_create(&serverEntry, @intFromPtr(&shared), 4);
    if (rc < 0) {
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" SKIP thread_create failed\n");
        return;
    }
    const server_handle: u64 = @bitCast(rc);

    _ = syscall.set_affinity(a_mask);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    t.waitUntilNonZero(&shared.server_ready);

    // Warmup
    var w: u32 = 0;
    while (w < 100) {
        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(server_handle, &.{0x42}, &reply);
        w += 1;
    }

    // Allocate measurement buffer via demand paging
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" SKIP alloc failed\n");
        return;
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

    // Signal server to exit
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(server_handle, &.{0xDEAD}, &reply);

    const result = bench.computeStats(buf, ITERATIONS);
    bench.report(name, result);
}

const Shared = struct {
    server_ready: u64 = 0,
    b_affinity: u64 = 1,
};

fn serverEntry() void {
    const shared: *Shared = @ptrFromInt(asm volatile (""
        : [ret] "={rdi}" (-> u64),
    ));

    _ = syscall.set_affinity(shared.b_affinity);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    @atomicStore(u64, &shared.server_ready, 1, .release);

    while (true) {
        var msg: syscall.IpcMessage = .{};
        const rc = syscall.ipc_recv(true, &msg);
        if (rc != 0) break;
        if (!msg.from_call) continue;

        if (msg.words[0] == 0xDEAD) {
            _ = syscall.ipc_reply(&.{0});
            break;
        }

        _ = syscall.ipc_reply(&.{msg.words[0]});
    }

    syscall.thread_exit();
}
