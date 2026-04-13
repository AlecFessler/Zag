const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.71 — For `pinned`, `set_priority` scans the calling thread's affinity mask in ascending core ID order for a core with no pinned owner; returns the pinned core ID (non-negative) in rax on success.
pub fn main(pv_addr: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv_addr);

    // Set affinity to cores 1 and 2.
    _ = syscall.set_affinity(0b110);

    // Pin — should succeed and return the pinned core ID (>= 0).
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret < 0) {
        t.failWithVal("§2.2.71 pin", 1, ret);
        syscall.shutdown();
    }
    t.pass("§2.2.71 pin returns core ID");

    // Verify core ID is 1 (first core in affinity mask 0b110).
    if (ret != 1) {
        t.failWithVal("§2.2.71 expected core 1", 1, ret);
        syscall.shutdown();
    }

    // Verify thread entry field1 shows pinned core ID.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    var found = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_THREAD and e.handle == self_handle) {
            if (e.field1 == 1) {
                t.pass("§2.2.71 thread field1=1");
            } else {
                t.failWithVal("§2.2.71 thread field1", 1, @bitCast(e.field1));
            }
            found = true;
            break;
        }
    }
    if (!found) {
        t.fail("§2.2.71 thread entry not found");
    }

    // Clean up.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
