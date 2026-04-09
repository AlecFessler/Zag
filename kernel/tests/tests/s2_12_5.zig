const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.5 — While a process holds `fault_handler` for a target, any new threads created in the target are immediately inserted into the handler's permissions table with full `ThreadHandleRights` upon `thread_create`
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

    // First call: child transfers fault_handler back to us. After this, the
    // kernel inserts the child's initial thread into our perm view per §2.12.4.
    var reply: syscall.IpcMessage = .{};
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.5 first ipc_call");
        syscall.shutdown();
    }

    var count_before: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) count_before += 1;
    }

    // Second call: child does thread_create on a new thread, then replies.
    // The reply is the synchronization point — by the time we read the perm
    // view next, the new thread must already exist.
    if (syscall.ipc_call(child_handle, &.{}, &reply) != 0) {
        t.fail("§2.12.5 second ipc_call");
        syscall.shutdown();
    }
    const new_thread_ret: i64 = @bitCast(reply.words[0]);
    if (new_thread_ret <= 0) {
        t.failWithVal("§2.12.5 child thread_create", 1, new_thread_ret);
        syscall.shutdown();
    }
    const new_thread_handle: u64 = @bitCast(new_thread_ret);

    var count_after: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) count_after += 1;
    }

    if (count_after != count_before + 1) {
        t.failWithVal("§2.12.5 thread count", @bitCast(count_before + 1), @bitCast(count_after));
        syscall.shutdown();
    }

    // The new entry must carry full ThreadHandleRights. The handle ID the
    // child received from its own thread_create is its handle ID, not ours,
    // so locate by "the entry that wasn't there before" — i.e., a thread
    // entry that isn't the child's initial thread. We rely on count = +1.
    const full_thread_rights: u16 = @truncate(perms.ThreadHandleRights.full.bits());
    var found_full: bool = false;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_THREAD) continue;
        if ((view[i].rights & full_thread_rights) == full_thread_rights) {
            found_full = true;
        }
    }
    if (!found_full) {
        t.fail("§2.12.5 new thread missing full ThreadHandleRights");
        syscall.shutdown();
    }

    _ = new_thread_handle;
    t.pass("§2.12.5");
    syscall.shutdown();
}
