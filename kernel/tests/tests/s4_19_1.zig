const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.19.1 — `reply` returns `E_OK` on success.
/// Verified by: call child_ipc_server, which calls ipc_reply internally.
/// If reply had failed (non-zero), child_ipc_server breaks its loop and the caller
/// wouldn't receive the expected reply payload. A successful round-trip with correct
/// payload proves reply returned E_OK.
pub fn main(_: u64) void {
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_ipc_server.ptr), children.child_ipc_server.len, child_rights.bits())));
    // Do two round-trips to prove the reply loop works (first reply didn't break the loop).
    var reply: syscall.IpcMessage = .{};
    const rc1 = syscall.ipc_call(ch, &.{0x42}, &reply);
    const ok1 = rc1 == 0 and reply.words[0] == 0x43;
    const rc2 = syscall.ipc_call(ch, &.{0x99}, &reply);
    const ok2 = rc2 == 0 and reply.words[0] == 0x9A;
    if (ok1 and ok2) {
        t.pass("§4.19.1");
    } else {
        t.fail("§4.19.1");
    }
    syscall.shutdown();
}
