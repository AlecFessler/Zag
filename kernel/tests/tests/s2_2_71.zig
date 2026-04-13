const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.71 — For `pinned`, `set_priority` scans the calling thread's affinity mask in ascending core ID order for a core with no pinned owner; returns the pinned core ID (positive) in rax on success.
pub fn main(pv_addr: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv_addr);

    // Set affinity to cores 1 and 2.
    _ = syscall.set_affinity(0b110);

    // Pin — should succeed and return a positive handle.
    const ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (ret <= 0) {
        t.failWithVal("§2.2.71 pin", 1, ret);
        syscall.shutdown();
    }
    t.pass("§2.2.71 pin returns handle");

    // Verify core_pin entry exists in perm view with field0 = 1 (core 1, first in mask).
    const handle: u64 = @bitCast(ret);
    var found = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_CORE_PIN and e.handle == handle) {
            if (e.field0 == 1) {
                t.pass("§2.2.71 core_pin field0=1");
            } else {
                t.failWithVal("§2.2.71 core_pin field0", 1, @bitCast(e.field0));
            }
            found = true;
            break;
        }
    }
    if (!found) {
        t.fail("§2.2.71 core_pin entry not found");
    }

    // Clean up.
    _ = syscall.revoke_perm(handle);
    syscall.shutdown();
}
