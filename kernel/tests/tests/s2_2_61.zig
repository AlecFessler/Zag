const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.2.61 — `thread_kill` on a thread in `.faulted` state returns `E_BUSY`
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child that transfers fault_handler then faults.
    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§2.2.61 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);
    _ = child_handle;

    // Acquire fault_handler via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(child_ret), &.{}, &reply);

    // Child will now fault (null dereference). Receive the fault.
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        t.failWithVal("§2.2.61 fault_recv", 0, recv_ret);
        syscall.shutdown();
    }

    // Find the faulted thread handle in perm_view.
    // Skip slot 1 — that's the parent's own initial thread handle.
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            break;
        }
    }

    if (thread_handle == 0) {
        t.fail("§2.2.61 no thread handle found");
        syscall.shutdown();
    }

    // Attempting to kill a faulted thread should return E_BUSY.
    const kill_ret = syscall.thread_kill(thread_handle);
    t.expectEqual("§2.2.61", E_BUSY, kill_ret);

    syscall.shutdown();
}
