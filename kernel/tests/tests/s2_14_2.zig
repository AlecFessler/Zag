const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.2 — `ThreadHandleRights.pmu` gates whether the caller may operate on a specific thread's PMU state; it is required in addition to `ProcessRights.pmu` for every PMU syscall that takes a thread handle.
pub fn main(_: u64) void {
    // Spawn child WITH ProcessRights.pmu but whose initial thread handle
    // lacks ThreadHandleRights.pmu. All four thread-operating PMU syscalls
    // must return E_PERM.
    const child_rights = perms.ProcessRights{ .pmu = true };
    const thread_rights = perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = true,
        .kill = true,
        // .pmu intentionally omitted
    };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_pmu_no_thread_right.ptr),
        children.child_pmu_no_thread_right.len,
        child_rights.bits(),
        thread_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    const start_rc: i64 = @bitCast(reply.words[0]);
    const read_rc: i64 = @bitCast(reply.words[1]);
    const reset_rc: i64 = @bitCast(reply.words[2]);
    const stop_rc: i64 = @bitCast(reply.words[3]);

    if (start_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.2 pmu_start", syscall.E_PERM, start_rc);
        syscall.shutdown();
    }
    if (read_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.2 pmu_read", syscall.E_PERM, read_rc);
        syscall.shutdown();
    }
    if (reset_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.2 pmu_reset", syscall.E_PERM, reset_rc);
        syscall.shutdown();
    }
    if (stop_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.2 pmu_stop", syscall.E_PERM, stop_rc);
        syscall.shutdown();
    }

    t.pass("§2.14.2");
    syscall.shutdown();
}
