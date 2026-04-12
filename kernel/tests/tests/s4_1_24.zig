const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §4.1.24 — `fault_reply` with `FAULT_KILL` kills the faulting thread.
/// If it is the last non-exited thread, process exit or restart proceeds
/// per §2.6.
///
/// Strong test: two scenarios.
///
/// Scenario A (multi-thread case): spawn a multi-threaded child with an
/// external handler; only the main thread null-derefs. Reply with
/// FAULT_KILL. Verify the faulted thread's handle is removed from our
/// perm view while sibling thread handles remain and the child's
/// entry stays `process` (not `dead_process`) — proving "kills only
/// the faulting thread" when it is not the last thread.
///
/// Scenario B (last-thread case): single-threaded child faults; reply
/// with FAULT_KILL; the child transitions to `dead_process`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // ====== Scenario A: multi-thread child, kill only the faulter ======

    const mt_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const mt_child: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_multithread_fault_after_transfer.ptr),
        children.child_multithread_fault_after_transfer.len,
        mt_rights,
    )));

    var mt_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == mt_child) {
            mt_slot = i;
            break;
        }
    }

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(mt_child, &.{}, &reply);

    // Snapshot thread handle IDs for the child (delta from before we
    // called the child; after acquisition we expect its main + worker).
    var fault_msg: syscall.FaultMessage = undefined;
    const mt_token = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (mt_token <= 0) {
        t.fail("§4.1.24 A fault_recv");
        syscall.shutdown();
    }
    const mt_token_u: u64 = @bitCast(mt_token);

    // Count thread entries BEFORE the kill so we can verify siblings
    // survive. Exclude root's own slot-1 thread by ID match with the
    // fault token (the faulting thread's handle is the token).
    var thread_count_before: u32 = 0;
    var siblings_before: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        thread_count_before += 1;
        if (view[i].handle != mt_token_u and i != 1) siblings_before += 1;
    }

    if (syscall.fault_reply_simple(mt_token_u, syscall.FAULT_KILL) != 0) {
        t.fail("§4.1.24 A fault_reply");
        syscall.shutdown();
    }

    // The killed faulter's entry must be gone; the child process must
    // still be alive; sibling threads must remain.
    var found_faulter = false;
    var siblings_after: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        if (view[i].handle == mt_token_u) found_faulter = true;
        if (view[i].handle != mt_token_u and i != 1) siblings_after += 1;
    }

    if (found_faulter) {
        t.fail("§4.1.24 A faulter handle not removed");
        syscall.shutdown();
    }
    if (view[mt_slot].entry_type != perm_view.ENTRY_TYPE_PROCESS) {
        t.fail("§4.1.24 A child died (should stay alive)");
        syscall.shutdown();
    }
    if (siblings_after == 0 or siblings_after < siblings_before) {
        t.failWithVal("§4.1.24 A siblings lost", @bitCast(@as(u64, siblings_before)), @bitCast(@as(u64, siblings_after)));
        syscall.shutdown();
    }

    // ====== Scenario B: single-thread child, kill last thread -> dead ======

    const single_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const single_child: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        single_rights,
    )));

    var single_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == single_child) {
            single_slot = i;
            break;
        }
    }

    _ = syscall.ipc_call(single_child, &.{}, &reply);

    var fault_msg2: syscall.FaultMessage = undefined;
    const s_token = syscall.fault_recv(@intFromPtr(&fault_msg2), 1);
    if (s_token <= 0) {
        t.fail("§4.1.24 B fault_recv");
        syscall.shutdown();
    }
    _ = syscall.fault_reply_simple(@bitCast(s_token), syscall.FAULT_KILL);

    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        if (view[single_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    if (view[single_slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.fail("§4.1.24 B child did not become dead_process");
        syscall.shutdown();
    }

    t.pass("§4.1.24");
    syscall.shutdown();
}
