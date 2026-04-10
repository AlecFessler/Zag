const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.15.2 — `pin_exclusive` requires both `ProcessRights.pin_exclusive` on slot 0 AND `ThreadHandleRights.set_affinity` on the `thread_handle`; returns `E_PERM` if either is absent.
///
/// Covers both branches (process bit missing, then thread-handle bit missing).
pub fn main(_: u64) void {
    // -- Branch 1: missing ProcessRights.pin_exclusive. --
    // (Include set_affinity so the child can still configure its affinity mask.)
    const p1_rights = (perms.ProcessRights{ .set_affinity = true }).bits();
    const ch1: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_try_pin_exclusive.ptr),
        children.child_try_pin_exclusive.len,
        p1_rights,
        (perms.ThreadHandleRights.full).bits(),
    )));
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch1, &.{}, &reply1);
    const r1: i64 = @bitCast(reply1.words[0]);
    t.expectEqual("§4.15.2 missing ProcessRights.pin_exclusive", E_PERM, r1);

    // -- Branch 2: process has both pin_exclusive and set_affinity, but the
    // thread handle lacks ThreadHandleRights.set_affinity. --
    const p2_rights = (perms.ProcessRights{
        .set_affinity = true,
        .pin_exclusive = true,
    }).bits();
    const t2_rights = (perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = true,
        .set_affinity = false,
    }).bits();
    const ch2: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_try_pin_exclusive.ptr),
        children.child_try_pin_exclusive.len,
        p2_rights,
        t2_rights,
    )));
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch2, &.{}, &reply2);
    const r2: i64 = @bitCast(reply2.words[0]);
    t.expectEqual("§4.15.2 missing ThreadHandleRights.set_affinity", E_PERM, r2);

    syscall.shutdown();
}
