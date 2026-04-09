const lib = @import("lib");

/// Triggers a fault on the overflow guard page above the stack.
/// Reads RSP, then writes 64KB above it to hit the guard.
pub fn main(_: u64) void {
    _ = lib;
    // RSP starts near the top of the usable stack. The overflow guard page
    // is at the next page boundary above the stack top. Round RSP up to the
    // next page boundary to land in the overflow guard.
    const rsp = asm ("mov %%rsp, %[rsp]"
        : [rsp] "=r" (-> u64),
    );
    const page_size: u64 = 4096;
    const guard_page = (rsp + page_size) & ~(page_size - 1);
    const above_stack: *volatile u8 = @ptrFromInt(guard_page);
    above_stack.* = 0;
}
