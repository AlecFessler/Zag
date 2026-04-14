const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.30 — When a thread calls `set_priority(.pinned)`, the kernel scans the thread's current affinity mask in ascending core ID order for a core with no pinned owner.
///
/// Set affinity to cores 1 and 2 (0b110). Pin. The return value should be 1
/// (lowest core in the mask) and the thread's user view entry field1 should
/// reflect the pinned core ID.
pub fn main(pv: u64) void {
    _ = syscall.set_affinity(0b110);
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret < 0) {
        t.failWithVal("§2.2.30 pin failed", 1, ret);
        syscall.shutdown();
    }

    // The return value is the pinned core ID — should be 1.
    if (ret != 1) {
        t.failWithVal("§2.2.30 expected core 1 from return", 1, ret);
        syscall.shutdown();
    }

    // Find our thread entry in the perm view and verify field1 has the pinned core ID.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var found = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_THREAD and e.handle == self_handle) {
            if (e.field1 == 1) {
                t.pass("§2.2.30 pinned to lowest core in mask");
            } else {
                t.failWithVal("§2.2.30 expected core 1 in field1", 1, @bitCast(e.field1));
            }
            found = true;
            break;
        }
    }
    if (!found) {
        t.fail("§2.2.30 thread entry not found in perm_view");
    }

    // Unpin.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
