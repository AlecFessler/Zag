const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.29.1 — `thread_self` returns the handle ID of the calling thread as it appears in the calling process's permissions table.
pub fn main(pv: u64) void {
    const handle = syscall.thread_self();
    if (handle <= 0) {
        t.failWithVal("§4.29.1 positive handle", 1, handle);
        syscall.shutdown();
    }

    // Verify the handle exists in the perm_view as a thread entry.
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const handle_u64: u64 = @bitCast(handle);

    // Scan perm_view entries to find the matching thread handle.
    var found = false;
    for (0..128) |i| {
        const entry = view[i];
        if (entry.entry_type == perm_view.ENTRY_TYPE_EMPTY) continue;
        if (entry.handle == handle_u64 and entry.entry_type == perm_view.ENTRY_TYPE_THREAD) {
            found = true;
            break;
        }
    }

    if (found) {
        t.pass("§4.29.1");
    } else {
        t.fail("§4.29.1 handle not found in perm_view");
    }
    syscall.shutdown();
}
