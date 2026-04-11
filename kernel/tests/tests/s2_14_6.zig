const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.14.6 — The only way a process may hold `ThreadHandleRights.pmu` on another process's threads is to hold `fault_handler` for that process.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const our_self_handle: u64 = @bitCast(syscall.thread_self());

    // Spawn a child that will cap-transfer fault_handler back to us.
    const child_rights = perms.ProcessRights{ .fault_handler = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    )));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    // Receive the fault so we know the kernel has inserted the child's
    // thread handle into our permission table.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.failWithVal("§2.14.6 fault_recv", 0, token);
        syscall.shutdown();
    }

    // Walk the perm view and find any THREAD entry that is not our own.
    // By §2.14.6, every such entry must carry ThreadHandleRights.pmu.
    const pmu_bit: u16 = @truncate((perms.ThreadHandleRights{ .pmu = true }).bits());
    var found_any = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        if (e.handle == our_self_handle) continue;
        found_any = true;
        if ((e.rights & pmu_bit) == 0) {
            t.fail("§2.14.6 debuggee thread handle lacks pmu right");
            _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
            syscall.shutdown();
        }
    }
    if (!found_any) {
        t.fail("§2.14.6 no debuggee thread handle found");
        _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    t.pass("§2.14.6");
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    syscall.shutdown();
}
