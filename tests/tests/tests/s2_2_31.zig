const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// §2.2.31 — A pinned thread cannot call `set_affinity`; attempting it returns `E_BUSY`.
pub fn main(_: u64) void {
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.failWithVal("§2.2.31 pin failed", 1, pin_ret);
        syscall.shutdown();
    }

    // While pinned, set_affinity should return E_BUSY.
    const ret = syscall.set_affinity(0b10);
    t.expectEqual("§2.2.31 set_affinity while pinned", E_BUSY, ret);

    // Unpin.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    syscall.shutdown();
}
