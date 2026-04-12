const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

var child_h: u64 = 0;
var result1: u64 = 0;
var result2: u64 = 0;
var done1: u64 align(8) = 0;
var done2: u64 align(8) = 0;

fn caller1() void {
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_h, &.{0x1000}, &reply);
    @atomicStore(u64, &result1, reply.words[0], .release);
    @atomicStore(u64, &done1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done1), 1);
}

fn caller2() void {
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_h, &.{0x2000}, &reply);
    @atomicStore(u64, &result2, reply.words[0], .release);
    @atomicStore(u64, &done2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done2), 1);
}

/// §3.3.9 — `recv` dequeues the first waiter from the wait queue and copies its payload.
///
/// Two callers send distinct payloads (0x1000 and 0x2000). child_ipc_server
/// replies with word[0]+1 per call. If recv truly copies each caller's
/// payload to the receiver, the replies should be 0x1001 and 0x2001 (one
/// for each caller, regardless of ordering). If recv failed to copy, we'd
/// see identical or zero replies.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    child_h = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_server.ptr),
        children.child_ipc_server.len,
        child_rights.bits(),
    )));

    _ = syscall.thread_create(&caller1, 0, 4);
    _ = syscall.thread_create(&caller2, 0, 4);

    t.waitUntilNonZero(&done1);
    t.waitUntilNonZero(&done2);

    const r1 = @atomicLoad(u64, &result1, .acquire);
    const r2 = @atomicLoad(u64, &result2, .acquire);

    // Both distinct payloads must round-trip: {0x1001, 0x2001} in some order.
    const ok = (r1 == 0x1001 and r2 == 0x2001) or (r1 == 0x2001 and r2 == 0x1001);
    if (ok) {
        t.pass("§3.3.9");
    } else {
        t.failWithVal("§3.3.9", 0x1001, @bitCast(r1));
    }
    syscall.shutdown();
}
