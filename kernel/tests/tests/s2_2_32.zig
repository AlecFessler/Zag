const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.32 — There are two ways to unpin: (1) call `thread_unpin` on the thread's handle, which restores the pre-pin affinity mask and drops priority to the pre-pin level; (2) call `set_priority` with any non-pinned level, which implicitly unpins, restores affinity, and applies the new priority.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const self_handle: u64 = @bitCast(syscall.thread_self());

    // --- Path 1: thread_unpin ---
    _ = syscall.set_affinity(0b10);
    const pin1 = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin1 < 0) {
        t.failWithVal("§2.2.32 pin1 failed", 0, pin1);
        syscall.shutdown();
    }

    // Unpin via thread_unpin.
    const unpin_ret = syscall.thread_unpin(self_handle);
    t.expectOk("§2.2.32 path1 thread_unpin", unpin_ret);

    // Verify field1 is cleared (no longer pinned).
    var field1_cleared = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_THREAD and e.handle == self_handle) {
            field1_cleared = (e.field1 == 0);
            break;
        }
    }
    if (!field1_cleared) {
        t.fail("§2.2.32 path1 field1 not cleared after unpin");
        syscall.shutdown();
    }

    // Verify we can set_affinity again (no longer pinned).
    const aff_ret = syscall.set_affinity(0b1);
    t.expectOk("§2.2.32 path1 affinity restored", aff_ret);

    // Verify priority is no longer pinned: set_priority(NORMAL) should succeed.
    const pri_ret = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.2.32 path1 priority restored", pri_ret);

    // --- Path 2: set_priority to non-pinned ---
    _ = syscall.set_affinity(0b10);
    const pin2 = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin2 < 0) {
        t.failWithVal("§2.2.32 pin2 failed", 0, pin2);
        syscall.shutdown();
    }

    // Set to NORMAL — should implicitly unpin.
    const set_ret = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.2.32 path2 set_priority NORMAL", set_ret);

    // Verify field1 is cleared in the thread's perm_view entry.
    var field1_gone = false;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_THREAD and e.handle == self_handle) {
            field1_gone = (e.field1 == 0);
            break;
        }
    }
    if (field1_gone) {
        t.pass("§2.2.32 path2 field1 cleared after implicit unpin");
    } else {
        t.fail("§2.2.32 path2 field1 still set after implicit unpin");
    }

    syscall.shutdown();
}
