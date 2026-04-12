const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §4.1.20 — `fault_reply` returns `E_INVAL` if the fault box is not in `pending_reply` state
pub fn main(_: u64) void {
    // Call fault_reply without ever calling fault_recv — the fault box is not
    // in pending_reply state, so the kernel must return E_INVAL.
    const rc = syscall.fault_reply_simple(0, syscall.FAULT_RESUME);
    t.expectEqual("§4.1.20", E_INVAL, rc);
    syscall.shutdown();
}
