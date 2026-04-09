const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn worker() void {
    // Stay alive long enough for the parent to inspect perm view.
    for (0..20) |_| syscall.thread_yield();
    syscall.thread_exit();
}

/// §2.4.2 — `thread_create` inserts a thread handle into the calling process's permissions table with full `ThreadHandleRights` and returns the handle ID (positive u64) on success
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const ret = syscall.thread_create(&worker, 0, 4);
    if (ret <= 0) {
        t.failWithVal("§2.4.2 thread_create", 1, ret);
        syscall.shutdown();
    }
    const thread_handle: u64 = @bitCast(ret);

    // Scan perm view for the returned handle.
    var found = false;
    var correct_type = false;
    var correct_rights = false;
    for (0..128) |i| {
        if (view[i].handle == thread_handle) {
            found = true;
            correct_type = view[i].entry_type == perm_view.ENTRY_TYPE_THREAD;
            const expected_rights: u16 = @as(u16, @as(u8, @bitCast(perms.ThreadHandleRights.full)));
            correct_rights = view[i].rights == expected_rights;
            break;
        }
    }

    if (found and correct_type and correct_rights) {
        t.pass("§2.4.2");
    } else if (!found) {
        t.fail("§2.4.2 handle not found in perm view");
    } else if (!correct_type) {
        t.fail("§2.4.2 wrong entry type");
    } else {
        t.fail("§2.4.2 wrong rights");
    }
    syscall.shutdown();
}
