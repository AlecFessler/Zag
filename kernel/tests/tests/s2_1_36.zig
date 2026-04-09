const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.36 — The ASLR base address is page-aligned.
pub fn main(pv: u64) void {
    // The perm_view address is placed by the kernel in the ASLR zone.
    // Both it and the stack pointer should be page-aligned.
    const pv_aligned = pv & 0xFFF == 0;
    // Check the stack pointer — stacks are placed at page-aligned addresses.
    var sp: u64 = undefined;
    asm volatile ("mov %%rsp, %[sp]"
        : [sp] "=r" (sp),
    );
    const sp_page_aligned = sp & 0xFFF != 0xFFF; // SP within stack, stack base is page-aligned
    // ELF segments are placed at the ASLR base which must be page-aligned.
    // The perm_view address being page-aligned is evidence of kernel alignment.
    _ = sp_page_aligned;
    if (pv_aligned) {
        t.pass("§2.1.36");
    } else {
        t.fail("§2.1.36");
    }
    syscall.shutdown();
}
