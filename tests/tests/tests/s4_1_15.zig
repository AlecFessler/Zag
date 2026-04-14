const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// Worker-thread shared state. The worker calls fault_recv BEFORE any
// fault is available; main arranges the fault later, proving blocking.
var worker_entered: u64 = 0;
var worker_token: i64 = 0;
var worker_done: u64 = 0;
var worker_fault_buf: syscall.FaultMessage = undefined;

fn workerThread() void {
    // Announce that we're about to enter fault_recv. Main can observe this
    // flag and confirm we reach fault_recv before the fault is arranged.
    @atomicStore(u64, &worker_entered, 1, .seq_cst);
    const tok = syscall.fault_recv(@intFromPtr(&worker_fault_buf), 1);
    worker_token = tok;
    @atomicStore(u64, &worker_done, 1, .seq_cst);
    syscall.thread_exit();
}

/// §4.1.15 — `fault_recv` with the blocking flag set blocks until a fault message is available in the calling process's fault box.
/// message is available in the calling process's fault box.
///
/// Strong test: issue fault_recv from a worker thread BEFORE any fault
/// has been arranged. Observe (a) the worker reached the fault_recv site,
/// (b) the worker's `done` flag stayed zero across a yield window (proof
/// of blocking), (c) only after the parent thread arranges a fault
/// delivery does the worker's `done` flag flip, and (d) the worker
/// received a valid positive token.
pub fn main(_: u64) void {
    // Spawn the worker. It immediately blocks on fault_recv because root
    // has no faults pending (root holds fault_handler on slot 0 per
    // §2.1.14).
    const wret = syscall.thread_create(&workerThread, 0, 4);
    if (wret < 0) {
        t.failWithVal("§4.1.15 thread_create", 0, wret);
        syscall.shutdown();
    }

    // Wait for the worker to actually reach its fault_recv call.
    while (@atomicLoad(u64, &worker_entered, .seq_cst) == 0) {
        syscall.thread_yield();
    }

    // Observation window (a): the worker has called fault_recv and must
    // still be blocked because no fault exists. Yield many times and
    // confirm `worker_done` stays zero — this is the proof of blocking.
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        if (@atomicLoad(u64, &worker_done, .seq_cst) != 0) {
            t.fail("§4.1.15 worker unblocked with no fault pending");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }

    // Arrange a fault via a separate child that cap-transfers HANDLE_SELF
    // + fault_handler to us and then null-derefs.
    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Wait for the worker to unblock and record a valid token.
    var drain: u32 = 0;
    while (drain < 500_000) : (drain += 1) {
        if (@atomicLoad(u64, &worker_done, .seq_cst) != 0) break;
        syscall.thread_yield();
    }
    if (@atomicLoad(u64, &worker_done, .seq_cst) == 0) {
        t.fail("§4.1.15 worker still blocked after fault arranged");
        syscall.shutdown();
    }
    if (worker_token <= 0) {
        t.failWithVal("§4.1.15 worker token", 1, worker_token);
        syscall.shutdown();
    }

    // Clean up: reply to the pending fault.
    _ = syscall.fault_reply_simple(@bitCast(worker_token), syscall.FAULT_KILL);

    t.pass("§4.1.15");
    syscall.shutdown();
}
