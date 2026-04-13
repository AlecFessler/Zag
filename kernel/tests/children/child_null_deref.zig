const lib = @import("lib");

pub fn main(_: u64) void {
    // Read from address 0 — should fault.
    lib.fault.nullDeref();
}
