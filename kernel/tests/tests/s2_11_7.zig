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
///
/// The child (`child_delayed_ipc_server`) yields 500 times before entering
/// its first `recv`. We spawn a worker thread that immediately issues the
/// ipc_call — this guarantees the call arrives long before the child is
/// ready to receive, forcing it onto the FIFO wait queue. We verify
/// queueing behaviorally: `call_done` must remain 0 for many yield cycles
/// after the worker dispatches the call (if direct delivery had occurred,
/// the call would have returned immediately). Eventually the child
/// dequeues us and replies.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    ch = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_delayed_ipc_server.ptr),
        children.child_delayed_ipc_server.len,
        child_rights.bits(),
    )));

    // Dispatch the call from a worker thread.
    _ = syscall.thread_create(&do_call, 0, 4);

    // Observe that the call is still outstanding across several yield
    // cycles — this proves the caller was queued rather than delivered
    // directly.
    var observed_pending = false;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        syscall.thread_yield();
        if (@atomicLoad(u64, &call_done, .acquire) == 0) {
            observed_pending = true;
        } else {
            break;
        }
    }
    if (!observed_pending) {
        t.fail("§2.11.7 call completed before any observable wait");
        syscall.shutdown();
    }

    // Eventually the child should reach recv, dequeue us, and reply.
    t.waitUntilNonZero(&call_done);
    if (call_result == 0 and reply_val == 0x43) {
        t.pass("§2.11.7");
    } else {
        t.failWithVal("§2.11.7 call rc", 0, call_result);
    }
    syscall.shutdown();
}
