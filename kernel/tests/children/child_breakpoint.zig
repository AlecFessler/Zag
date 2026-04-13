const lib = @import("lib");

/// Executes a breakpoint instruction to trigger a #BP/BRK fault.
pub fn main(_: u64) void {
    lib.fault.breakpoint();
}
