const lib = @import("lib");

/// Triggers a divide-by-zero fault.
pub fn main(_: u64) void {
    _ = lib;
    const zero: u64 = 0;
    _ = asm ("div %[divisor]"
        : [_] "={rax}" (-> u64),
        : [divisor] "r" (zero),
          [_] "{rax}" (@as(u64, 1)),
          [_] "{rdx}" (@as(u64, 0)),
    );
}
