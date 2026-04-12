const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §4.1.16 — `fault_recv` with the blocking flag clear returns `E_AGAIN` if no fault message is pending
/// message is pending.
pub fn main(_: u64) void {
    // Root service has fault_handler in ProcessRights (all rights set per §2.1.14),
    // so fault_recv won't return E_PERM. With no faults pending and blocking=0,
    // it should return E_AGAIN.
    var fault_msg: syscall.FaultMessage = undefined;
    const rc = syscall.fault_recv(@intFromPtr(&fault_msg), 0);

    t.expectEqual("§4.1.16", E_AGAIN, rc);
    syscall.shutdown();
}
