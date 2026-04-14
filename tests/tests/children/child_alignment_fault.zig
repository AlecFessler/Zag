const lib = @import("lib");

/// Triggers an alignment check fault. Arch-specific mechanism, see
/// `lib.fault.alignmentFault`.
pub fn main(_: u64) void {
    lib.fault.alignmentFault();
}
