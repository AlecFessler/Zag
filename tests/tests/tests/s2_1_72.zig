const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const STATIC_ZONE_START: u64 = 0x0000_1000_0000_0000;

/// §2.1.72 — ELF segments and stacks are never placed in the static reservation zone `[0x0000_1000_0000_0000, 0xFFFF_8000_0000_0000)`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Code address (this function) should be below the static zone.
    const code_addr = @intFromPtr(&main);
    // Stack address (local variable).
    var stack_var: u64 = 0;
    stack_var += 1;
    const stack_addr = @intFromPtr(&stack_var);
    if (code_addr < STATIC_ZONE_START and stack_addr < STATIC_ZONE_START) {
        t.pass("§2.1.72");
    } else {
        t.fail("§2.1.72");
    }
    syscall.shutdown();
}
