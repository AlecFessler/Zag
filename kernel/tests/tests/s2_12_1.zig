const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §2.12.1 — `ProcessRights` bit 7 is `fault_handler`.
///
/// When set on a process's slot 0, the process handles its own faults in
/// its own fault box. This bit is granted at `proc_create` time if
/// included in the `process_rights` parameter.
///
/// Observable: spawn a multi-threaded self-handler via `proc_create` with
/// `fault_handler=true` in the ProcessRights argument. Force one of its
/// threads to fault. The fault must be delivered to the child's OWN fault
/// box (proved by the child's own `fault_recv` returning the token from
/// inside the child and reporting it back to us via IPC), and must NOT
/// appear in the parent's fault box.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that creates a faulting worker thread and blocks in
    // its OWN fault_recv, then reports the received token to us via IPC.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_self_handle_multithread_fault.ptr),
        children.child_self_handle_multithread_fault.len,
        child_rights,
    )));

    // Locate the child's slot.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    // Drain anything that might already be in our fault box before the
    // child runs. The parent is root — it holds fault_handler in its own
    // ProcessRights per §2.1.14, so fault_recv is permitted and returns
    // E_AGAIN when empty.
    var pre_buf: syscall.FaultMessage = undefined;
    const pre_rc = syscall.fault_recv(@intFromPtr(&pre_buf), 0);
    if (pre_rc != E_AGAIN) {
        t.failWithVal("§2.12.1 pre fault_recv not empty", E_AGAIN, pre_rc);
        syscall.shutdown();
    }

    // IPC the child: it will spawn the faulter, block in its own fault_recv,
    // receive the fault, then reply to us with the fault token. If the
    // fault_handler bit on slot 0 did NOT grant self-handling, the fault
    // would be routed elsewhere and the child's fault_recv would never
    // return — the ipc_call would time out / block indefinitely.
    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call(child_handle, &.{}, &reply);
    if (call_rc != 0) {
        t.failWithVal("§2.12.1 ipc_call", 0, call_rc);
        syscall.shutdown();
    }

    const child_token: i64 = @bitCast(reply.words[0]);
    if (child_token <= 0) {
        t.failWithVal("§2.12.1 child fault_recv token", 1, child_token);
        syscall.shutdown();
    }

    // The child is still alive — the reply came from its main thread AFTER
    // fault_recv returned, proving the fault was routed to its own box and
    // the process wasn't killed.
    if (view[slot].entry_type != perm_view.ENTRY_TYPE_PROCESS) {
        t.fail("§2.12.1 child died unexpectedly");
        syscall.shutdown();
    }
    if (view[slot].processRestartCount() != 0) {
        t.fail("§2.12.1 child restarted (fault went to wrong box)");
        syscall.shutdown();
    }

    // And the parent's fault box must NOT have received any message about
    // the child — the bit on slot 0 routes faults to the child's OWN box,
    // not ours.
    var post_buf: syscall.FaultMessage = undefined;
    const post_rc = syscall.fault_recv(@intFromPtr(&post_buf), 0);
    if (post_rc != E_AGAIN) {
        t.failWithVal("§2.12.1 fault leaked to parent", E_AGAIN, post_rc);
        syscall.shutdown();
    }

    t.pass("§2.12.1");
    syscall.shutdown();
}
