const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.35 — On restart of a process that has an external fault handler: all thread handles for that process are bulk-revoked from the handler's permissions table; the fresh initial thread handle is immediately inserted into the handler's permissions table with full `ThreadHandleRights`; the `fault_handler` relationship (fault_handler_proc pointer) persists across restart without requiring re-transfer.
/// all thread handles for that process are bulk-revoked from the handler's
/// permissions table; the fresh initial thread handle is immediately
/// inserted with full ThreadHandleRights; the fault_handler relationship
/// persists without re-transfer.
///
/// We record the pre-restart thread handle IDs (multiple — the child spawns
/// extra parker threads), drive a fault that triggers restart, then verify:
///   * every pre-restart thread id is GONE from our perm view
///   * exactly one fresh thread handle is present with a different id
///   * that fresh entry has full ThreadHandleRights
///   * the fault_handler process handle still has `fault_handler` bit set
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn restartable child with fault_handler right.
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .restart = true,
        .fault_handler = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fh_threads_then_fault.ptr),
        children.child_fh_threads_then_fault.len,
        child_rights.bits(),
    )));

    // First call: child replies with HANDLE_SELF + fault_handler bit.
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply1);

    // Find the process-handle-with-fault_handler we received.
    const fh_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var fh_proc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit) != 0)
        {
            fh_proc_handle = view[i].handle;
            break;
        }
    }

    // Wait until all three of the child's threads (main + 2 parkers) appear
    // in our perm view as thread entries. Because our own initial thread is
    // at slot 1, we look for thread entries whose tid doesn't match our
    // slot-1 tid.
    const our_thread_tid = view[1].threadTid();

    var pre_ids: [8]u64 = undefined;
    var n_pre: usize = 0;
    var wait_iters: u32 = 0;
    while (wait_iters < 300000) : (wait_iters += 1) {
        n_pre = 0;
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
                view[i].threadTid() != our_thread_tid)
            {
                if (n_pre < pre_ids.len) {
                    pre_ids[n_pre] = view[i].handle;
                    n_pre += 1;
                }
            }
        }
        if (n_pre >= 3) break;
        syscall.thread_yield();
    }

    if (n_pre < 3) {
        t.fail("§2.6.35 pre threads");
        syscall.shutdown();
    }

    // Second call: tells the child to proceed and fault.
    var reply2: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply2);

    // Receive the fault and reply FAULT_KILL — this kills only the faulting
    // thread and releases all `.suspended` siblings back to `.ready` per
    // §2.12.23. The parker workers then exist as alive threads, so the
    // process doesn't restart yet. We then thread_kill the workers (via the
    // handles we hold as external fault handler) — the last non-exited
    // thread exiting triggers restart (§2.4.18), which is what we want to
    // observe.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token <= 0) {
        t.fail("§2.6.35 fault_recv");
        syscall.shutdown();
    }
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    // Kill every pre-restart thread handle. The faulting thread is already
    // gone so its handle returns an error, which we ignore; the two parkers
    // get killed and the last one triggers restart.
    {
        var k: usize = 0;
        while (k < n_pre) : (k += 1) {
            _ = syscall.thread_kill(pre_ids[k]);
        }
    }

    // Wait for the child's restart_count to advance.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var ra: u32 = 0;
    while (ra < 500000) : (ra += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }

    // Collect post-restart thread entries (excluding our own slot-1 thread).
    var post_count: usize = 0;
    var post_ids: [8]u64 = undefined;
    var new_entry_idx: usize = 0xFFFF;
    var probe: u32 = 0;
    while (probe < 200000) : (probe += 1) {
        post_count = 0;
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
                view[i].threadTid() != our_thread_tid)
            {
                if (post_count < post_ids.len) {
                    post_ids[post_count] = view[i].handle;
                    new_entry_idx = i;
                    post_count += 1;
                }
            }
        }
        if (post_count >= 1) break;
        syscall.thread_yield();
    }

    // All pre ids must be gone.
    var all_pre_gone = true;
    var pi: usize = 0;
    while (pi < n_pre) : (pi += 1) {
        var j: usize = 0;
        while (j < post_count) : (j += 1) {
            if (post_ids[j] == pre_ids[pi]) {
                all_pre_gone = false;
                break;
            }
        }
        if (!all_pre_gone) break;
    }

    // Exactly one new thread handle.
    const exactly_one_new = post_count == 1;

    // Full thread rights on the new entry.
    const full_tr: u16 = @truncate(perms.ThreadHandleRights.full.bits());
    const full_rights_ok = new_entry_idx != 0xFFFF and
        (view[new_entry_idx].rights & full_tr) == full_tr;

    // fault_handler relationship persists.
    var fh_persists = false;
    if (fh_proc_handle != 0) {
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
                view[i].handle == fh_proc_handle and
                (view[i].rights & fh_bit) != 0)
            {
                fh_persists = true;
                break;
            }
        }
    }

    if (all_pre_gone and exactly_one_new and full_rights_ok and fh_persists) {
        t.pass("§2.6.35");
    } else {
        t.fail("§2.6.35");
    }
    syscall.shutdown();
}
