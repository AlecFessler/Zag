const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

/// `set_affinity` returns `E_BUSY` if the calling thread is currently pinned.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Set single-core affinity, then pin.
    _ = syscall.set_affinity(0b1);
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret <= 0) {
        t.failWithVal("§4.14.5 setup pin", 1, pin_ret);
        syscall.shutdown();
    }
    // Now try to change affinity while pinned.
    const ret = syscall.set_affinity(0x1);
    t.expectEqual("§4.14.5", E_BUSY, ret);
    // Clean up: revoke pin handle.
    _ = syscall.revoke_perm(@bitCast(pin_ret));
    syscall.shutdown();
}
