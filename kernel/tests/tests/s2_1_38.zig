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

/// §2.1.38 — Thread entry `field1` exposes the fault-handler exclude flags: bit 0 = `exclude_oneshot`, bit 1 = `exclude_permanent`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child and acquire fault_handler rights over it via cap transfer.
    // The child parks in `futex_wait` so the thread handle stays live for the
    // duration of this test.
    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Locate the child's thread entry that the cap transfer installed in our
    // perm view.
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != 0) {
            thread_handle = view[i].handle;
            break;
        }
    }
    if (thread_handle == 0) {
        t.fail("§2.1.38 no thread handle found");
        syscall.shutdown();
    }

    // EXCLUDE_NEXT → bit 0 set, bit 1 clear.
    const rc1 = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    if (rc1 != 0) {
        t.failWithVal("§2.1.38 EXCLUDE_NEXT rc", 0, rc1);
        syscall.shutdown();
    }
    if (findThreadEntry(view, thread_handle)) |e| {
        if (!(e.threadExcludeOneshot() and !e.threadExcludePermanent())) {
            t.fail("§2.1.38 EXCLUDE_NEXT: expected bit0=1, bit1=0");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.1.38 thread entry vanished");
        syscall.shutdown();
    }

    // EXCLUDE_PERMANENT → bit 0 clear, bit 1 set.
    const rc2 = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    if (rc2 != 0) {
        t.failWithVal("§2.1.38 EXCLUDE_PERMANENT rc", 0, rc2);
        syscall.shutdown();
    }
    if (findThreadEntry(view, thread_handle)) |e| {
        if (!(!e.threadExcludeOneshot() and e.threadExcludePermanent())) {
            t.fail("§2.1.38 EXCLUDE_PERMANENT: expected bit0=0, bit1=1");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.1.38 thread entry vanished");
        syscall.shutdown();
    }

    // STOP_ALL → both bits clear.
    const rc3 = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_STOP_ALL);
    if (rc3 != 0) {
        t.failWithVal("§2.1.38 STOP_ALL rc", 0, rc3);
        syscall.shutdown();
    }
    if (findThreadEntry(view, thread_handle)) |e| {
        if (e.threadExcludeOneshot() or e.threadExcludePermanent()) {
            t.fail("§2.1.38 STOP_ALL: expected both bits clear");
            syscall.shutdown();
        }
    } else {
        t.fail("§2.1.38 thread entry vanished");
        syscall.shutdown();
    }

    t.pass("§2.1.38");
    syscall.shutdown();
}
