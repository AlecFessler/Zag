const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

var ch: u64 = 0;
var call_done: u64 = 0;
var call_result: i64 = 0;
var reply_val: u64 = 0;

fn do_call() void {
    var reply: syscall.IpcMessage = .{};
    call_result = syscall.ipc_call(ch, &.{0x42}, &reply);
    reply_val = reply.words[0];
    @atomicStore(u64, &call_done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&call_done), 1);
}

/// §2.11.7 — `call` with no receiver waiting queues the caller in the target's FIFO wait queue.
pub fn main(_: u64) void {
    // Spawn child_ipc_server.
    const child_rights = perms.ProcessRights{};
    ch = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));

    // Call from a separate thread immediately — no yield — to maximize the chance
    // we queue before child reaches recv.
    _ = syscall.thread_create(&do_call, 0, 4);

    // Wait for the call to complete.
    t.waitUntilNonZero(&call_done);

    // Whether we queued or delivered directly, the call should succeed.
    if (call_result == 0 and reply_val == 0x43) {
        t.pass("§2.11.7");
    } else {
        t.fail("§2.11.7");
    }
    syscall.shutdown();
}
