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
    _ = lib.syscall.delete(lib.caps.SLOT_SELF);
    while (true) asm volatile ("hlt");
}
