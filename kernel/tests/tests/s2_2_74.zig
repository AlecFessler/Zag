const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §2.2.74 — `set_priority` with a non-pinned level while currently pinned implicitly unpins the thread, restores the pre-pin affinity mask, clears `field1` in the thread's user view entry, and applies the new priority.
pub fn main(pv: u64) void {
    // Pin the thread first.
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.failWithVal("§2.2.74 pin failed", 0, pin_ret);
        syscall.shutdown();
    }

    // Now set a non-pinned priority — this should implicitly unpin.
    const ret = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectEqual("§2.2.74", E_OK, ret);

    // Verify field1 is cleared in the thread's user view entry.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type == perm_view.ENTRY_TYPE_THREAD and e.handle == self_handle) {
            if (e.field1 != 0) {
                t.failWithVal("§2.2.74 field1 not cleared", 0, @bitCast(e.field1));
            }
            break;
        }
    }

    syscall.shutdown();
}
