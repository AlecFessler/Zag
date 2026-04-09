const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.24 — `fault_reply` with `FAULT_KILL` kills the faulting thread.
/// If it is the last non-exited thread, process exit or restart proceeds per §2.6.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler then faults.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);

    if (token < 0) {
        t.fail("§2.12.24 fault_recv failed");
        syscall.shutdown();
    }

    // Reply with FAULT_KILL — this kills the faulting thread.
    const rc = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);

    if (rc != 0) {
        t.fail("§2.12.24 fault_reply failed");
        syscall.shutdown();
    }

    // The child had only one thread, so killing it should cause process exit.
    // Wait for the child to become a dead_process entry in the perm view.
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        for (0..128) |i| {
            if (view[i].handle == child_handle and
                view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS)
            {
                t.pass("§2.12.24");
                syscall.shutdown();
            }
        }
        syscall.thread_yield();
    }

    t.fail("§2.12.24 child did not become dead_process");
    syscall.shutdown();
}
