const lib = @import("lib");

/// Trivial child for the spawn workload — loaded, started, returns
/// immediately to exercise the full spawn/teardown path.
pub fn main(_: u64) void {
    _ = lib;
}
