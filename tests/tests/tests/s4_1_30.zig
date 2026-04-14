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

/// §4.1.30 — `fault_set_thread_mode` with mode `exclude_next` sets `exclude_oneshot` and clears `exclude_permanent`.
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
        t.fail("§4.1.30 no thread handle");
        syscall.shutdown();
    }

    // Seed exclude_permanent so we can verify exclude_next clears it.
    _ = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);

    const rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    if (rc != 0) {
        t.failWithVal("§4.1.30 exclude_next rc", 0, rc);
        syscall.shutdown();
    }

    if (findThreadEntry(view, thread_handle)) |e| {
        if (e.threadExcludeOneshot() and !e.threadExcludePermanent()) {
            t.pass("§4.1.30");
        } else {
            t.fail("§4.1.30 wrong flag state after exclude_next");
        }
    } else {
        t.fail("§4.1.30 thread entry vanished");
    }
    syscall.shutdown();
}
