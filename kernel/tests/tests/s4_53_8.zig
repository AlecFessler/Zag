const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.53.8 — `pmu_reset` with `configs_ptr` not pointing to a readable region of `count * sizeof(PmuCounterConfig)` bytes returns `E_BADADDR`.
pub fn main(_: u64) void {
    var info: syscall.PmuInfo = undefined;
    if (syscall.pmu_info(@intFromPtr(&info)) != syscall.E_OK or
        info.num_counters == 0 or info.overflow_support == 0)
    {
        t.pass("§4.53.8");
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
        t.failWithVal("§4.53.8 fault_recv", 0, token);
        syscall.shutdown();
    }
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));

    const rc = syscall.pmu_reset(fm.thread_handle, 0, 1);
    t.expectEqual("§4.53.8", syscall.E_BADADDR, rc);

    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
