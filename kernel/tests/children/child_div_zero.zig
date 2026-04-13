const builtin = @import("builtin");
const lib = @import("lib");

/// Triggers a divide-by-zero fault on x86. aarch64 does not raise an
/// exception for integer division by zero, so we substitute an illegal
/// instruction which produces an equivalent synchronous crash.
pub fn main(_: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const zero: u64 = 0;
            _ = asm ("div %[divisor]"
                : [_] "={rax}" (-> u64),
                : [divisor] "r" (zero),
                  [_] "{rax}" (@as(u64, 1)),
                  [_] "{rdx}" (@as(u64, 0)),
            );
        },
        .aarch64 => lib.fault.illegalInstruction(),
        else => unreachable,
    }
}
