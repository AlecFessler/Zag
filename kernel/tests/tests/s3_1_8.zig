const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §3.1.8 — `mem_shm_create` requires `mem_shm_create` right — returns `E_PERM` without it.
pub fn main(_: u64) void {
    // Spawn child WITHOUT mem_shm_create right
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_try_shm_create.ptr), children.child_try_shm_create.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const child_result: i64 = @bitCast(reply.words[0]);
    t.expectEqual("§3.1.8", E_PERM, child_result);
    syscall.shutdown();
}
