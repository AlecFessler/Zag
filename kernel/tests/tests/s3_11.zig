const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.11 — A counter overflow on a thread with PMU state configured for sample-based profiling delivers a fault with reason `pmu_overflow`; `FaultMessage.fault_addr` contains the faulting RIP and the full register snapshot in `FaultMessage.regs` is the sample.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or
        info.num_counters == 0 or info.overflow_support == 0)
    {
        t.pass("§3.11");
        syscall.shutdown();
    }

    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .pmu = true,
    };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_pmu_overflow.ptr),
        children.child_pmu_overflow.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§3.11 fault_recv", 0, token);
        syscall.shutdown();
    }

    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    if (fm.fault_reason != syscall.FAULT_REASON_PMU_OVERFLOW) {
        t.failWithVal("§3.11 fault_reason",
            syscall.FAULT_REASON_PMU_OVERFLOW, @intCast(fm.fault_reason));
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }
    // fault_addr and regs.rip must both hold the faulting RIP (the sample).
    if (fm.fault_addr == 0 or fm.rip == 0) {
        t.fail("§3.11 fault_addr / rip zero");
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }
    if (fm.fault_addr != fm.rip) {
        t.failWithVal("§3.11 fault_addr != rip",
            @bitCast(fm.rip), @bitCast(fm.fault_addr));
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    t.pass("§3.11");
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
