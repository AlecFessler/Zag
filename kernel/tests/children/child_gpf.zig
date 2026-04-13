const lib = @import("lib");

/// Triggers a general protection fault by executing a privileged instruction.
pub fn main(_: u64) void {
    lib.fault.privilegedInstruction();
}
