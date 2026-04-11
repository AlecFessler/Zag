const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.1 — `ProcessRights.pmu` gates whether a process may call any PMU syscall that operates on thread state; without it, `pmu_start`, `pmu_read`, `pmu_reset`, and `pmu_stop` return `E_PERM`.
pub fn main(_: u64) void {
    // Spawn child WITHOUT ProcessRights.pmu but with everything needed to
    // run. All four thread-operating PMU syscalls inside the child must
    // return E_PERM.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_try_pmu_all.ptr),
        children.child_try_pmu_all.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    const start_rc: i64 = @bitCast(reply.words[0]);
    const read_rc: i64 = @bitCast(reply.words[1]);
    const reset_rc: i64 = @bitCast(reply.words[2]);
    const stop_rc: i64 = @bitCast(reply.words[3]);

    if (start_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.1 pmu_start", syscall.E_PERM, start_rc);
        syscall.shutdown();
    }
    if (read_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.1 pmu_read", syscall.E_PERM, read_rc);
        syscall.shutdown();
    }
    if (reset_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.1 pmu_reset", syscall.E_PERM, reset_rc);
        syscall.shutdown();
    }
    if (stop_rc != syscall.E_PERM) {
        t.failWithVal("§2.14.1 pmu_stop", syscall.E_PERM, stop_rc);
        syscall.shutdown();
    }

    t.pass("§2.14.1");
    syscall.shutdown();
}
