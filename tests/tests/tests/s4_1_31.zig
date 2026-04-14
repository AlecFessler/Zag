const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, h: u64) ?*const perm_view.UserViewEntry {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle == h) {
            return &view[i];
        }
    }
    return null;
}

/// §4.1.31 — `fault_set_thread_mode` with mode `exclude_permanent` sets `exclude_permanent` and clears `exclude_oneshot`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            thread_handle = view[i].handle;
            break;
        }
    }
    if (thread_handle == 0) {
        t.fail("§4.1.31 no thread handle");
        syscall.shutdown();
    }

    // Seed exclude_oneshot so we can verify exclude_permanent clears it.
    _ = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);

    const rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    if (rc != 0) {
        t.failWithVal("§4.1.31 exclude_permanent rc", 0, rc);
        syscall.shutdown();
    }

    if (findThreadEntry(view, thread_handle)) |e| {
        if (e.threadExcludePermanent() and !e.threadExcludeOneshot()) {
            t.pass("§4.1.31");
        } else {
            t.fail("§4.1.31 wrong flag state after exclude_permanent");
        }
    } else {
        t.fail("§4.1.31 thread entry vanished");
    }
    syscall.shutdown();
}
