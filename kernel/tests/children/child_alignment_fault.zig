const lib = @import("lib");

/// Triggers an alignment check fault by enabling AC flag and doing misaligned access.
pub fn main(_: u64) void {
    _ = lib;
    // Enable AC (alignment check) flag in RFLAGS and do misaligned access
    asm volatile (
        \\pushfq
        \\orq $0x40000, (%%rsp)
        \\popfq
        \\movq %%rsp, %%rax
        \\addq $1, %%rax
        \\movq (%%rax), %%rbx
    );
}
