const lib = @import("lib");

/// Triggers an illegal instruction fault (UD2 / UDF).
pub fn main(_: u64) void {
    lib.fault.illegalInstruction();
}
