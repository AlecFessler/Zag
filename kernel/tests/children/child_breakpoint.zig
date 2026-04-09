const lib = @import("lib");

/// Executes int3 to trigger a breakpoint fault.
pub fn main(_: u64) void {
    _ = lib;
    asm volatile ("int3");
}
