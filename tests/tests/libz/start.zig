const app = @import("app");
const lib = @import("lib");

// Per §[create_capability_domain]: "The pointer to the new domain's
// read-only view of its capability table is passed as the first
// argument to the initial EC's entry point." On x86-64 SysV that's
// rdi at entry; the linker script puts _start in .text._start so the
// kernel jumps to it as an ordinary function call.
export fn _start(cap_table_base: u64) noreturn {
    app.main(cap_table_base);
    // Fall-through: drop the self-handle, which per spec §[delete]
    // cleans up the calling capability domain.
    //
    // Must use `issueRegDiscard` directly. ReleaseSmall LLVM otherwise
    // strips the entire `issueReg → issueRawNoStack` chain when the
    // returned `Regs` is unused — the chain has 13 output operands
    // none of which feed any side-effecting consumer downstream, so
    // the optimizer proves the chain dead and removes the inner
    // `asm volatile` along with it. The visible failure was the test
    // EC reaching `hlt` with its CD (and any periodic timer it had
    // armed) still live; the leaked timer would then fire forever
    // through `propagateAndWake` and starve the runner past iter
    // ~416, producing the cascade-MISS tail.
    lib.syscall.issueRegDiscard(.delete, 0, .{ .v1 = lib.caps.SLOT_SELF });
    while (true) asm volatile ("hlt");
}
