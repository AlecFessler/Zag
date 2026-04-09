const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.4 — When a process acquires `fault_handler` for a target, the kernel immediately inserts thread handles for all of the target's current threads into the acquirer's permissions table with full `ThreadHandleRights`
/// inserts thread handles for all of the target's current threads into the acquirer's
/// permissions table with full ThreadHandleRights.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child with fault_handler right so it can transfer it to us.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .fault_handler = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_fault_handler.ptr),
        children.child_send_self_fault_handler.len,
        child_rights.bits(),
    )));

    // Count thread entries before acquiring fault_handler.
    var thread_count_before: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_count_before += 1;
        }
    }

    // Call the child — it replies with HANDLE_SELF via cap transfer with fault_handler bit.
    // This makes us the fault handler, which should insert thread handles.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Count thread entries after acquiring fault_handler.
    // The child has 1 thread (its initial thread), so we should see 1 new ENTRY_TYPE_THREAD.
    var thread_count_after: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_count_after += 1;
        }
    }

    // Verify at least one new thread handle appeared.
    if (thread_count_after > thread_count_before) {
        // Also verify the thread handle has full ThreadHandleRights (0x0F).
        const full_thread_rights: u16 = @truncate(perms.ThreadHandleRights.full.bits());
        var has_full_rights = false;
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and
                (view[i].rights & full_thread_rights) == full_thread_rights)
            {
                has_full_rights = true;
                break;
            }
        }
        if (has_full_rights) {
            t.pass("§2.12.4");
        } else {
            t.fail("§2.12.4");
        }
    } else {
        t.failWithVal("§2.12.4", @bitCast(thread_count_before + 1), @bitCast(thread_count_after));
    }
    syscall.shutdown();
}
