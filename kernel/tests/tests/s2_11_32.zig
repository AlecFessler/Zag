const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;

var child_handle: u64 = 0;
var call_result_1: i64 = 0;
var call_result_2: i64 = 0;
var done_1: u64 = 0;
var done_2: u64 = 0;

fn caller1() void {
    var reply: syscall.IpcMessage = .{};
    call_result_1 = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &done_1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done_1), 1);
}

fn caller2() void {
    var reply: syscall.IpcMessage = .{};
    call_result_2 = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &done_2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done_2), 1);
}

/// §2.11.32 — When a process dies, queued callers in its wait queue are unblocked with `E_NOENT`.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_sleep.ptr), children.child_sleep.len, child_rights.bits())));
    @atomicStore(u64, &child_handle, h, .release);

    syscall.thread_yield();
    syscall.thread_yield();

    // Two callers block in child's msg_waiters queue.
    _ = syscall.thread_create(&caller1, 0, 4);
    _ = syscall.thread_create(&caller2, 0, 4);

    syscall.thread_yield();
    syscall.thread_yield();

    // Kill child — both callers should get E_NOENT.
    _ = syscall.revoke_perm(h);

    t.waitUntilNonZero(&done_1);
    t.waitUntilNonZero(&done_2);
    const ok = (call_result_1 == E_NOENT) and (call_result_2 == E_NOENT);
    if (ok) t.pass("§2.11.32") else t.fail("§2.11.32");
    syscall.shutdown();
}
