const lib = @import("lib");

const bench = lib.bench;
const perm_view = lib.perm_view;
const syscall = lib.syscall;

const ITERATIONS: u32 = 5000;

/// IPC benchmark client. Root sends affinity then cap-transfers the
/// server handle. Client measures ipc_call round-trips to server,
/// then waits for root to call and replies with results.
pub fn main(pv: u64) void {
    // Recv affinity from root
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.set_affinity(msg.words[0]);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);
    _ = syscall.ipc_reply(&.{});

    // Recv cap transfer (server handle lands in our perm_view)
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    // Find server handle — the process entry that isn't slot 0
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var server_handle: u64 = 0;
    for (1..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            server_handle = view[i].handle;
            break;
        }
    }
    if (server_handle == 0) {
        // Report failure — wait for root to call, reply with zeros
        _ = syscall.ipc_recv(true, &msg);
        _ = syscall.ipc_reply(&.{ 0, 0, 0, 0, 0 });
        syscall.thread_exit();
    }

    // Warmup
    var w: u32 = 0;
    while (w < 200) {
        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call(server_handle, &.{0x42}, &reply);
        w += 1;
    }

    // Allocate measurement buffer
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        _ = syscall.ipc_recv(true, &msg);
        _ = syscall.ipc_reply(&.{ 0, 0, 0, 0, 0 });
        syscall.thread_exit();
    };
    const buf = buf_ptr[0..ITERATIONS];

    // Measurement loop
    var i: u32 = 0;
    while (i < ITERATIONS) {
        var reply: syscall.IpcMessage = .{};
        const t0 = bench.rdtscp();
        _ = syscall.ipc_call(server_handle, &.{0x42}, &reply);
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
        i += 1;
    }

    const result = bench.computeStats(buf, ITERATIONS);

    // Wait for root to ask for results, reply with them
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{
        result.min,
        result.median,
        result.mean,
        result.p99,
        result.max,
    });

    syscall.thread_exit();
}
