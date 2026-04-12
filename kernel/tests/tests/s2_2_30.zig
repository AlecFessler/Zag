const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.30 — When a thread calls `set_priority(.pinned)`, the kernel scans the thread's current affinity mask in ascending core ID order for a core with no pinned owner.
///
/// Set affinity to cores 1 and 2 (0b110). Pin. The core_pin entry's field0
/// should be 1 (lowest core in the mask).
pub fn main(pv: u64) void {
    _ = syscall.set_affinity(0b110);
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret <= 0) {
        t.failWithVal("§2.2.30 pin failed", 1, ret);
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(ret);

    // Find the core_pin entry in perm_view and check field0 (pinned core ID).
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var found = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == pin_handle) {
            if (e.field0 == 1) {
                t.pass("§2.2.30 pinned to lowest core in mask");
            } else {
                t.failWithVal("§2.2.30 expected core 1", 1, @bitCast(e.field0));
            }
            found = true;
            break;
        }
    }
    if (!found) {
        t.fail("§2.2.30 core_pin entry not found in perm_view");
    }

    // Unpin.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
