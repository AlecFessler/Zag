const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.4 — `ProcessRights.pmu` flows to child processes via the `process_rights` parameter of `proc_create` under the usual subset rule.
pub fn main(_: u64) void {
    // Parent (root service) holds ProcessRights.pmu by §2.14.3. Spawn a
    // child requesting pmu and verify the child observes the bit.
    const with_pmu = perms.ProcessRights{ .pmu = true };
    const ch_yes: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_report_pmu_right.ptr),
        children.child_report_pmu_right.len,
        with_pmu.bits(),
    )));
    var reply_yes: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch_yes, &.{}, &reply_yes);
    if (reply_yes.words[0] != 1) {
        t.fail("§2.14.4 pmu did not flow into child");
        syscall.shutdown();
    }

    // Subset: spawn a second child without pmu — child must NOT see it.
    const without_pmu = perms.ProcessRights{};
    const ch_no: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_report_pmu_right.ptr),
        children.child_report_pmu_right.len,
        without_pmu.bits(),
    )));
    var reply_no: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch_no, &.{}, &reply_no);
    if (reply_no.words[0] != 0) {
        t.fail("§2.14.4 pmu leaked into subset-less child");
        syscall.shutdown();
    }

    t.pass("§2.14.4");
    syscall.shutdown();
}
