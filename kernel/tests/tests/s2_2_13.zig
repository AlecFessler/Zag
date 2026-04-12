const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn countChildThreadEntries(view: [*]const perm_view.UserViewEntry, our_self: u64) u32 {
    var n: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != our_self) {
            n += 1;
        }
    }
    return n;
}

/// §2.2.13 — When a thread exits, its handle entry is cleared from its owning process's permissions table.
///
/// External-handler cleanup path: we spawn a child that becomes our fault
/// debuggee via HANDLE_SELF + fault_handler cap transfer (§2.12.3). Per
/// §2.12.4 the child's initial thread handle is inserted into our perm
/// table; per §2.12.5 a thread the child subsequently creates is also
/// inserted. When that worker thread exits, §2.2.13 requires its handle to
/// be cleared from BOTH the child's own table and ours.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const our_self: u64 = @bitCast(@as(i64, syscall.thread_self()));

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_transfer_then_spawn_exit_worker.ptr),
        children.child_transfer_then_spawn_exit_worker.len,
        child_rights,
    )));

    // Acquire fault_handler for the child via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Immediately after the call we should see 1 child thread handle
    // (the child's main thread) in our perm view.
    const n0 = countChildThreadEntries(view, our_self);
    if (n0 == 0) {
        t.fail("§2.2.13 no child thread handle after fault_handler acquire");
        syscall.shutdown();
    }

    // The child will thread_create a worker that exits immediately. We
    // should see the child thread count rise to 2, then fall back to 1.
    var saw_worker_inserted = false;
    var saw_worker_removed = false;
    var iters: u32 = 0;
    while (iters < 5000) : (iters += 1) {
        syscall.thread_yield();
        const n = countChildThreadEntries(view, our_self);
        if (n >= n0 + 1) saw_worker_inserted = true;
        if (saw_worker_inserted and n == n0) {
            saw_worker_removed = true;
            break;
        }
    }

    if (saw_worker_inserted and saw_worker_removed) {
        t.pass("§2.2.13");
    } else if (!saw_worker_inserted) {
        t.fail("§2.2.13 worker thread handle never appeared in our view");
    } else {
        t.fail("§2.2.13 worker thread handle never cleared from our view");
    }
    syscall.shutdown();
}
