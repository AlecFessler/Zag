const lib = @import("lib");

/// Triggers a general protection fault by executing a privileged instruction (CLI).
pub fn main(_: u64) void {
    _ = lib;
    asm volatile ("cli");
}
