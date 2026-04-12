const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.8 — When a thread faults and the process is its own fault handler and multiple threads exist, the faulting thread enters `.faulted` state and a fault message is enqueued in the process's own fault box; all other threads continue running normally
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a self-handling child with two threads. The faulter null-derefs;
    // the main thread blocks in fault_recv on the child's own fault box. If
    // §4.1.8 holds, fault_recv returns the fault token, proving (a) a fault
    // message was enqueued in the process's own box, (b) the faulting thread
    // entered `.faulted` (the process wasn't killed/restarted as it would be
    // under §2.12.7), and (c) the main thread continued running normally
    // (it was not stop-all'd). The child reports the token back via IPC.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_self_handle_multithread_fault.ptr),
        children.child_self_handle_multithread_fault.len,
        child_rights,
    )));

    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }

    var reply: syscall.IpcMessage = .{};
    const call_rc = syscall.ipc_call(child_handle, &.{}, &reply);
    if (call_rc != 0) {
        t.failWithVal("§4.1.8 ipc_call", 0, call_rc);
        syscall.shutdown();
    }

    const token: i64 = @bitCast(reply.words[0]);
    if (token <= 0) {
        t.failWithVal("§4.1.8 fault_recv token", 1, token);
        syscall.shutdown();
    }

    // The reply was sent from inside the child *after* the fault was received,
    // so the child must still be alive (entry type unchanged, no restart).
    if (view[slot].entry_type != perm_view.ENTRY_TYPE_PROCESS) {
        t.fail("§4.1.8 child died");
        syscall.shutdown();
    }
    if (view[slot].processRestartCount() != 0) {
        t.fail("§4.1.8 child restarted (should not have)");
        syscall.shutdown();
    }

    t.pass("§4.1.8");
    syscall.shutdown();
}
