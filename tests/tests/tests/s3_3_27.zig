const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

var child_handle: u64 = 0;
var call_result: i64 = 0;
var caller_queued: u64 align(8) = 0;
var caller_done: u64 align(8) = 0;

fn caller_thread() void {
    // Signal we are about to enter ipc_call.
    @atomicStore(u64, &caller_queued, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&caller_queued), 1);
    var reply: syscall.IpcMessage = .{};
    call_result = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &caller_done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&caller_done), 1);
}

/// §3.3.27 — If a caller is blocked waiting for a reply, it is unblocked with `E_NOENT` on server death.
///
/// child_recv_noreply recvs exactly one message (making the caller a
/// pending_caller) and then blocks forever without replying. We spawn a
/// worker thread that issues ipc_call and signals `caller_queued` just
/// before entering the kernel. The parent waits for that flag and then
/// yields many times to ensure the call has actually reached the kernel
/// and been either queued or accepted into pending_caller state before
/// revoking the child. On revoke, the pending caller must be unblocked
/// with E_NOENT.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_recv_noreply.ptr),
        children.child_recv_noreply.len,
        child_rights.bits(),
    )));
    @atomicStore(u64, &child_handle, h, .release);

    _ = syscall.thread_create(&caller_thread, 0, 4);
    t.waitUntilNonZero(&caller_queued);

    // Yield enough times for the caller to enter the kernel, the child
    // to recv it (or queue it), and for the child to then block on its
    // futex. 2000 yields is the same slack used elsewhere in this
    // directory for "call has reached kernel state".
    for (0..2000) |_| syscall.thread_yield();

    _ = syscall.revoke_perm(h);

    t.waitUntilNonZero(&caller_done);
    t.expectEqual("§3.3.27", E_NOENT, call_result);
    syscall.shutdown();
}
