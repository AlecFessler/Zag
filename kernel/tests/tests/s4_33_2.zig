const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADADDR: i64 = -7;

/// §4.33.2 — `fault_recv` with `buf_ptr` not pointing to a writable region of at least `sizeof(FaultMessage)` bytes returns `E_BADADDR`
pub fn main(_: u64) void {
    // Pass an unmapped address as buf_ptr.
    const ret = syscall.fault_recv(0xDEAD, 1);
    t.expectEqual("§4.33.2", E_BADADDR, ret);

    syscall.shutdown();
}
