const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

extern const __ehdr_start: u8;

/// §2.1.76 — The ASLR base address is page-aligned.
pub fn main(_: u64) void {
    // `__ehdr_start` is a linker-provided symbol that resolves to the
    // in-memory address of the ELF header — i.e. the ASLR-randomized load
    // base itself. If the base is page-aligned, its low 12 bits are zero.
    const base: u64 = @intFromPtr(&__ehdr_start);
    if (base & 0xFFF == 0) {
        t.pass("§2.1.76");
    } else {
        t.failWithVal("§2.1.76", 0, @bitCast(base));
    }
    syscall.shutdown();
}
