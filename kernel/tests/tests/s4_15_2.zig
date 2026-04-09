const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.15.2 — `pin_exclusive` requires both `ProcessRights.pin_exclusive` on slot 0 AND `ThreadHandleRights.set_affinity` on the `thread_handle`; returns `E_PERM` if either is absent.
pub fn main(_: u64) void {
    // Spawn child WITHOUT pin_exclusive right (but with set_affinity for the pre-req)
    const child_rights = (perms.ProcessRights{ .set_affinity = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_try_pin_exclusive.ptr), children.child_try_pin_exclusive.len, child_rights)));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.15.2", E_PERM, child_result);
    syscall.shutdown();
}
