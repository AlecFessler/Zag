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

/// §2.12.29 — `fault_set_thread_mode` with mode `stop_all` clears both `exclude_oneshot` and `exclude_permanent` on the thread's perm entry in the caller's permissions table.
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
        t.fail("§2.12.29 no thread handle");
        syscall.shutdown();
    }

    // Pre-condition: set BOTH flags non-zero by setting permanent then mutating
    // oneshot via a separate call. We seed with permanent so post-stop_all clearing
    // is observable in field1.
    _ = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    if (findThreadEntry(view, thread_handle)) |e| {
        if (!e.threadExcludePermanent()) {
            t.fail("§2.12.29 setup: exclude_permanent not visible");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.12.29 thread entry vanished");
        syscall.shutdown();
    }

    const rc = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_STOP_ALL);
    if (rc != 0) {
        t.failWithVal("§2.12.29 stop_all rc", 0, rc);
        syscall.shutdown();
    }

    // Verify both flags are now CLEAR in field1 (sub-scenario A: permanent
    // was seeded — proves stop_all clears `exclude_permanent`).
    if (findThreadEntry(view, thread_handle)) |e| {
        if (e.threadExcludeOneshot() or e.threadExcludePermanent()) {
            t.fail("§2.12.29 A flags not cleared after stop_all");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.12.29 A thread entry vanished after stop_all");
        syscall.shutdown();
    }

    // Sub-scenario B: seed `exclude_oneshot`, then stop_all, and verify it
    // is also cleared. Without this, the "clears oneshot" clause of
    // §2.12.29 is vacuous (A only proves the permanent clause).
    _ = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    if (findThreadEntry(view, thread_handle)) |e| {
        if (!e.threadExcludeOneshot()) {
            t.fail("§2.12.29 B setup: exclude_oneshot not visible");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.12.29 B thread entry vanished during setup");
        syscall.shutdown();
    }

    const rc2 = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_STOP_ALL);
    if (rc2 != 0) {
        t.failWithVal("§2.12.29 B stop_all rc", 0, rc2);
        syscall.shutdown();
    }

    if (findThreadEntry(view, thread_handle)) |e| {
        if (!e.threadExcludeOneshot() and !e.threadExcludePermanent()) {
            t.pass("§2.12.29");
        } else {
            t.fail("§2.12.29 B flags not cleared after stop_all");
        }
    } else {
        t.fail("§2.12.29 B thread entry vanished after stop_all");
    }
    syscall.shutdown();
}
