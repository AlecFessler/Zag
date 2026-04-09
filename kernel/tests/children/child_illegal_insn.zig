const lib = @import("lib");

/// Triggers an illegal instruction fault via UD2.
pub fn main(_: u64) void {
    _ = lib;
    asm volatile ("ud2");
}
