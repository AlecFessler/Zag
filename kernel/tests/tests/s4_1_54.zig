const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §4.1.54 — `fault_recv` with blocking flag clear returns `E_AGAIN` when the fault box is empty
pub fn main(_: u64) void {
    // Call fault_recv non-blocking with no faults pending.
    var fault_msg: syscall.FaultMessage = undefined;
    const ret = syscall.fault_recv(@intFromPtr(&fault_msg), 0);
    t.expectEqual("§4.1.54", E_AGAIN, ret);

    syscall.shutdown();
}
