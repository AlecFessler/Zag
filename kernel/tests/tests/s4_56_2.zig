const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.56.2 — `clock_getwall` requires no rights and is callable by any process.
pub fn main(_: u64) void {
    // Spawn child with zero rights
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_clock_getwall.ptr),
        children.child_try_clock_getwall.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    // Child should have gotten a positive timestamp
    if (child_result > 0) {
        t.pass("§4.56.2");
    } else {
        t.failWithVal("§4.56.2", 1, child_result);
    }
    syscall.shutdown();
}
