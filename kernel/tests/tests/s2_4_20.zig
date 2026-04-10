const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.4.20 — `set_priority` is self-only (no thread handle parameter).
///
/// Tests:
///   1. Child without ProcessRights.set_affinity calling set_priority → E_PERM.
///   2. Child with max_thread_priority=normal trying set_priority(high) → E_PERM (exceeds ceiling).
///   3. Child with max_thread_priority=high trying set_priority(high) → success.
pub fn main(_: u64) void {
    // 1. Missing ProcessRights.set_affinity → E_PERM.
    {
        const child_rights = (perms.ProcessRights{}).bits();
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
            @intFromPtr(children.child_try_set_priority.ptr),
            children.child_try_set_priority.len,
            child_rights,
        )));
        var reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply);
        if (rc != 0) {
            t.failWithVal("§2.4.20 case1 ipc_call", 0, rc);
            syscall.shutdown();
        }
        const child_result: i64 = @bitCast(reply.words[0]);
        if (child_result != E_PERM) {
            t.failWithVal("§2.4.20 missing ProcessRights E_PERM", E_PERM, child_result);
            syscall.shutdown();
        }
    }

    // 2. max_thread_priority=normal, request high → E_PERM (exceeds ceiling).
    {
        const child_rights = (perms.ProcessRights{ .set_affinity = true }).bits();
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_opts(
            @intFromPtr(children.child_try_set_priority.ptr),
            children.child_try_set_priority.len,
            child_rights,
            perms.ThreadHandleRights.full.bits(),
            syscall.PRIORITY_NORMAL,
        )));
        var reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply);
        if (rc != 0) {
            t.failWithVal("§2.4.20 case2 ipc_call", 0, rc);
            syscall.shutdown();
        }
        const child_result: i64 = @bitCast(reply.words[0]);
        if (child_result != E_PERM) {
            t.failWithVal("§2.4.20 ceiling exceeded E_PERM", E_PERM, child_result);
            syscall.shutdown();
        }
    }

    // 3. max_thread_priority=high, request high → success.
    {
        const child_rights = (perms.ProcessRights{ .set_affinity = true }).bits();
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_opts(
            @intFromPtr(children.child_try_set_priority.ptr),
            children.child_try_set_priority.len,
            child_rights,
            perms.ThreadHandleRights.full.bits(),
            syscall.PRIORITY_HIGH,
        )));
        var reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(ch, &.{syscall.PRIORITY_HIGH}, &reply);
        if (rc != 0) {
            t.failWithVal("§2.4.20 case3 ipc_call", 0, rc);
            syscall.shutdown();
        }
        const child_result: i64 = @bitCast(reply.words[0]);
        if (child_result < 0) {
            t.failWithVal("§2.4.20 within ceiling should succeed", 0, child_result);
            syscall.shutdown();
        }
    }

    t.pass("§2.4.20");
    syscall.shutdown();
}
