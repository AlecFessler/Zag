const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.34.2 — `fault_reply` returns `E_INVAL` if the fault box is not in `pending_reply` state, if `action` is not a valid value (0, 1, or 2), or if both `FAULT_EXCLUDE_NEXT` and `FAULT_EXCLUDE_PERMANENT` flags are set simultaneously.
pub fn main(_: u64) void {
    // Call fault_reply when no fault has been received (fault box is empty/idle).
    const ret = syscall.fault_reply_simple(0, syscall.FAULT_KILL);
    t.expectEqual("§4.34.2", E_INVAL, ret);

    syscall.shutdown();
}
