const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

var child_h: u64 = 0;
var result1: u64 = 0;
var result2: u64 = 0;
var caller1_queued: u64 align(8) = 0;
var done1: u64 align(8) = 0;
var done2: u64 align(8) = 0;

fn caller1() void {
    @atomicStore(u64, &caller1_queued, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&caller1_queued), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_h, &.{0}, &reply);
    @atomicStore(u64, &result1, reply.words[0], .release);
    @atomicStore(u64, &done1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done1), 1);
}

fn caller2() void {
    while (@atomicLoad(u64, &caller1_queued, .acquire) == 0) {
        syscall.thread_yield();
    }
    for (0..10) |_| syscall.thread_yield();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_h, &.{0}, &reply);
    @atomicStore(u64, &result2, reply.words[0], .release);
    @atomicStore(u64, &done2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done2), 1);
}

/// §2.11.21 — The call wait queue is FIFO ordered.
pub fn main(_: u64) void {
    // Spawn child_ipc_counter: replies with sequential counter (1, 2, 3, ...).
    const child_rights = perms.ProcessRights{};
    child_h = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_counter.ptr),
        children.child_ipc_counter.len,
        child_rights.bits(),
    )));

    // Caller1 queues first, caller2 queues second.
    _ = syscall.thread_create(&caller1, 0, 4);
    _ = syscall.thread_create(&caller2, 0, 4);

    t.waitUntilNonZero(&done1);
    t.waitUntilNonZero(&done2);

    const r1 = @atomicLoad(u64, &result1, .acquire);
    const r2 = @atomicLoad(u64, &result2, .acquire);

    // FIFO: caller1 served first (counter=1), caller2 served second (counter=2).
    if (r1 == 1 and r2 == 2) {
        t.pass("§2.11.21");
    } else {
        t.failWithVal("§2.11.21", 1, @bitCast(r1));
    }
    syscall.shutdown();
}
