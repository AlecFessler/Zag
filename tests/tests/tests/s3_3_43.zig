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
    // Call the child — child is blocked on futex_wait, not receiving,
    // so this blocks in the child's msg_waiters queue.
    var reply: syscall.IpcMessage = .{};
    call_result = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &caller_done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&caller_done), 1);
}

/// §3.3.43 — `call`: target dies while caller is waiting returns `E_NOENT`.
pub fn main(_: u64) void {
    // Spawn child_sleep — it blocks on futex_wait forever.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_sleep.ptr), children.child_sleep.len, child_rights.bits())));
    @atomicStore(u64, &child_handle, h, .release);

    // Let child start and block on futex_wait.
    syscall.thread_yield();
    syscall.thread_yield();

    // Spawn caller thread — it will block on ipc_call to child.
    _ = syscall.thread_create(&caller_thread, 0, 4);

    // Let caller thread block in child's msg_waiters.
    for (0..5) |_| {
        syscall.thread_yield();
    }

    // Kill the child — this should wake the caller with E_NOENT.
    _ = syscall.revoke_perm(h);

    // Wait for caller thread to complete.
    t.waitUntilNonZero(&caller_done);
    t.expectEqual("§3.3.43", E_NOENT, call_result);
    syscall.shutdown();
}
