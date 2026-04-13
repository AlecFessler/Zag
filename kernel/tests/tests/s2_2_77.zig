const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §2.2.77 — `thread_unpin` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;

    // Pin on core 0.
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.failWithVal("§2.2.77 setup pin", 1, pin_ret);
        syscall.shutdown();
    }

    // Unpin via thread_unpin on self.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    const ret = syscall.thread_unpin(self_handle);
    t.expectEqual("§2.2.77", E_OK, ret);

    syscall.shutdown();
}
