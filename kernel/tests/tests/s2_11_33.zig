const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

var child_handle: u64 = 0;
var call_result: i64 = 0;
var caller_done: u64 = 0;

fn caller_thread() void {
    // Call the child — child will recv (making us pending_caller) but never reply.
    var reply: syscall.IpcMessage = .{};
    call_result = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &caller_done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&caller_done), 1);
}

/// §2.11.33 — If a caller is blocked waiting for a reply, it is unblocked with `E_NOENT` on server death.
pub fn main(_: u64) void {
    // Spawn child_recv_noreply — it receives but never replies, then blocks on futex.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_recv_noreply.ptr), children.child_recv_noreply.len, child_rights.bits())));
    @atomicStore(u64, &child_handle, h, .release);

    // Let child start and block on ipc_recv.
    syscall.thread_yield();
    syscall.thread_yield();

    // Spawn caller — child will recv the call (caller becomes pending_caller),
    // then child blocks on futex without replying.
    _ = syscall.thread_create(&caller_thread, 0, 4);

    // Let caller get delivered and child block on futex.
    syscall.thread_yield();
    syscall.thread_yield();
    syscall.thread_yield();

    // Kill child — caller should get E_NOENT.
    _ = syscall.revoke_perm(h);

    t.waitUntilNonZero(&caller_done);
    t.expectEqual("§2.11.33", E_NOENT, call_result);
    syscall.shutdown();
}
