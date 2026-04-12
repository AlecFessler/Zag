const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.81 — `proc_create` child starts with `HANDLE_SELF` at slot 0 and its initial thread handle at slot 1 with rights = `thread_rights`.
pub fn main(_: u64) void {
    // Spawn child_report_slot1 with specific thread_rights (suspend + kill).
    const child_proc_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    const thread_rights = perms.ThreadHandleRights{
        .@"suspend" = true,
        .@"resume" = false,
        .kill = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create_with_thread_rights(
        @intFromPtr(children.child_report_slot1.ptr),
        children.child_report_slot1.len,
        child_proc_rights.bits(),
        thread_rights.bits(),
    )));

    // Let child start.
    for (0..5) |_| syscall.thread_yield();

    // Call child to get slot 1 info: entry_type, handle, rights.
    var reply: syscall.IpcMessage = .{};
    const ret = syscall.ipc_call(child_handle, &.{}, &reply);
    if (ret != 0) {
        t.failWithVal("§2.1.81 ipc_call", 0, ret);
        syscall.shutdown();
    }

    const entry_type: u8 = @truncate(reply.words[0]);
    const handle = reply.words[1];
    const rights: u16 = @truncate(reply.words[2]);

    const expected_rights: u16 = @as(u16, @as(u8, @bitCast(thread_rights)));

    var pass_all = true;
    if (entry_type != perm_view.ENTRY_TYPE_THREAD) {
        t.fail("§2.1.81 slot 1 entry_type not THREAD");
        pass_all = false;
    }
    if (handle == 0) {
        t.fail("§2.1.81 slot 1 handle is zero");
        pass_all = false;
    }
    if (rights != expected_rights) {
        t.fail("§2.1.81 slot 1 rights mismatch");
        pass_all = false;
    }

    if (pass_all) {
        t.pass("§2.1.81");
    }
    syscall.shutdown();
}
