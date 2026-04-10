const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.37.1 — `fault_set_thread_mode` returns `E_OK` on success.
///
/// Also verify the corresponding field1 exclude flag bit actually changed in
/// the perm view.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = perms.ProcessRights{
        .fault_handler = true,
    };
    const child_ret = syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    );
    if (child_ret <= 0) {
        t.failWithVal("§4.37.1 proc_create", 1, child_ret);
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(child_ret);

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Find the child's thread handle (skip slot 1 = parent's own).
    var thread_handle: u64 = 0;
    var slot: usize = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            slot = i;
            break;
        }
    }
    if (thread_handle == 0) {
        t.fail("§4.37.1 no thread handle found");
        syscall.shutdown();
    }

    // Both flags should start clear.
    if (view[slot].threadExcludeOneshot() or view[slot].threadExcludePermanent()) {
        t.fail("§4.37.1 exclude flags non-zero pre-call");
        syscall.shutdown();
    }

    // EXCLUDE_NEXT flips the oneshot bit.
    const ret_next = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_NEXT);
    t.expectEqual("§4.37.1 EXCLUDE_NEXT rc", E_OK, ret_next);
    if (!view[slot].threadExcludeOneshot()) {
        t.fail("§4.37.1 oneshot bit not set");
        syscall.shutdown();
    }

    // EXCLUDE_PERMANENT flips the permanent bit.
    const ret_perm = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    t.expectEqual("§4.37.1 EXCLUDE_PERMANENT rc", E_OK, ret_perm);
    if (!view[slot].threadExcludePermanent()) {
        t.fail("§4.37.1 permanent bit not set");
        syscall.shutdown();
    }

    // STOP_ALL clears both.
    const ret_stop = syscall.fault_set_thread_mode(thread_handle, syscall.FAULT_MODE_STOP_ALL);
    t.expectEqual("§4.37.1 STOP_ALL rc", E_OK, ret_stop);
    if (view[slot].threadExcludeOneshot() or view[slot].threadExcludePermanent()) {
        t.fail("§4.37.1 exclude flags not cleared by STOP_ALL");
        syscall.shutdown();
    }

    t.pass("§4.37.1");
    syscall.shutdown();
}
