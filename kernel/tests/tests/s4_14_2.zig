const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.14.2 — `set_affinity` requires `set_affinity` right — returns `E_PERM` without it.
pub fn main(_: u64) void {
    // Spawn child WITHOUT set_affinity right
    const child_rights = perms.ProcessRights{};
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_try_affinity.ptr), children.child_try_affinity.len, child_rights.bits())));
    // Call child — child tries set_affinity and reports result
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§4.14.2", E_PERM, child_result);
    syscall.shutdown();
}
