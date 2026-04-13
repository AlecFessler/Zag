const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §2.2.81 — On success, `thread_unpin` restores the thread's pre-pin affinity mask, drops its priority to the pre-pin level, and clears `field1` in the thread's user view entry.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Set affinity to core 1 before pinning.
    _ = syscall.set_affinity(0b10);

    // Pin — should return the pinned core ID.
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.failWithVal("§2.2.81 setup pin", 1, pin_ret);
        syscall.shutdown();
    }

    // Verify field1 shows pinned core ID.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    var found_pinned = false;
    for (0..128) |i| {
        if (view[i].handle == self_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            if (view[i].field1 != 0) {
                found_pinned = true;
            }
            break;
        }
    }
    if (!found_pinned) {
        t.fail("§2.2.81 field1 not set while pinned");
        syscall.shutdown();
    }

    // Unpin via thread_unpin.
    const ret = syscall.thread_unpin(self_handle);
    t.expectEqual("§2.2.81 unpin", E_OK, ret);

    // Verify field1 is cleared.
    for (0..128) |i| {
        if (view[i].handle == self_handle and view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            if (view[i].field1 == 0) {
                t.pass("§2.2.81 field1 cleared");
            } else {
                t.fail("§2.2.81 field1 not cleared after unpin");
            }
            break;
        }
    }

    // Verify affinity was restored: set_affinity should succeed (not pinned).
    const aff_ret = syscall.set_affinity(0b1);
    t.expectOk("§2.2.81 affinity restored", aff_ret);

    // Verify priority was restored: set_priority to normal should succeed.
    const pri_ret = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.2.81 priority restored", pri_ret);

    syscall.shutdown();
}
