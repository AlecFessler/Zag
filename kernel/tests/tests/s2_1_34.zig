const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const ASLR_ZONE_START: u64 = 0x0000_0000_0000_1000;
const ASLR_ZONE_END: u64 = 0x0000_1000_0000_0000;

/// §2.1.34 — ELF segments and user stacks are placed in the ASLR zone `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)` with a randomized base.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const code_addr = @intFromPtr(&main);
    var stack_var: u64 = 0;
    stack_var += 1;
    const stack_addr = @intFromPtr(&stack_var);
    if (code_addr >= ASLR_ZONE_START and code_addr < ASLR_ZONE_END and
        stack_addr >= ASLR_ZONE_START and stack_addr < ASLR_ZONE_END)
    {
        t.pass("§2.1.34");
    } else {
        t.fail("§2.1.34");
    }
    syscall.shutdown();
}
