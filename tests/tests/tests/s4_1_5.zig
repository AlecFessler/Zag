const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.1.5 — While a process holds `fault_handler` for a target, any new threads created in the target are immediately inserted into the handler's permissions table with full `ThreadHandleRights` upon `thread_create`.
/// threads created in the target are immediately inserted into the handler's
/// permissions table with full `ThreadHandleRights` upon `thread_create`.
///
/// Strong test: snapshot thread handle IDs both pre-acquisition and
/// post-acquisition. After the child creates one new thread, find the
/// single delta entry (compared to the post-acquisition snapshot) and
/// verify ONLY that entry's rights — eliminating the weakness of
/// accepting any pre-existing thread entry as "full rights found".
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self_then_create_thread.ptr),
        children.child_send_self_then_create_thread.len,
        child_rights,
    )));

    // First ipc_call: child cap-transfers HANDLE_SELF + fault_handler.
    // Per §2.12.4 the child's initial thread handle now exists in our
    // table.
    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§4.1.5 first ipc_call");
        syscall.shutdown();
    }

    // Snapshot: thread handle IDs currently in our table (includes the
    // child's initial thread and root's own initial thread).
    var post_acq_ids: [128]u64 = .{0} ** 128;
    var post_acq_count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            post_acq_ids[post_acq_count] = view[i].handle;
            post_acq_count += 1;
        }
    }

    // Second ipc_call: child calls thread_create on a new worker and then
    // replies — the reply is the barrier, so by the time we read the perm
    // view below, the new thread has definitely been inserted into our
    // table per §2.12.5.
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§4.1.5 second ipc_call");
        syscall.shutdown();
    }
    const child_thread_create_ret: i64 = @bitCast(reply.words[0]);
    if (child_thread_create_ret <= 0) {
        t.failWithVal("§4.1.5 child thread_create", 1, child_thread_create_ret);
        syscall.shutdown();
    }

    // Find the delta: the single new thread entry not present in the
    // post-acquisition snapshot.
    const full_rights: u16 = @truncate(perms.ThreadHandleRights.full.bits());
    var delta_count: u32 = 0;
    var delta_rights: u16 = 0;
    outer: for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        const h = view[i].handle;
        for (0..post_acq_count) |k| {
            if (post_acq_ids[k] == h) continue :outer;
        }
        delta_count += 1;
        delta_rights = view[i].rights;
    }

    if (delta_count != 1) {
        t.failWithVal("§4.1.5 delta count", 1, @bitCast(@as(u64, delta_count)));
        syscall.shutdown();
    }
    if ((delta_rights & full_rights) != full_rights) {
        t.failWithVal("§4.1.5 delta rights", @intCast(full_rights), @intCast(delta_rights));
        syscall.shutdown();
    }

    t.pass("§4.1.5");
    syscall.shutdown();
}
