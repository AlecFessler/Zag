const lib = @import("lib");

pub fn main(_: u64) void {
    _ = lib;
    // Read from address 0 — should fault.
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true }
    );
}
