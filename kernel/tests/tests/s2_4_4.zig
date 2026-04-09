const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.4 — `thread_self` returns the handle ID of the calling thread as it appears in the calling process's own permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const ret = syscall.thread_self();
    if (ret <= 0) {
        t.failWithVal("§2.4.4 thread_self", 1, ret);
        syscall.shutdown();
    }
    const self_handle: u64 = @bitCast(ret);

    // Verify the handle exists in our perm view as a thread entry.
    var found = false;
    for (0..128) |i| {
        if (view[i].handle == self_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            found = true;
            break;
        }
    }

    if (found) {
        t.pass("§2.4.4");
    } else {
        t.fail("§2.4.4 thread_self handle not found in perm view");
    }
    syscall.shutdown();
}
