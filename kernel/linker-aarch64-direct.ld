/* aarch64 direct-kernel linker script.
 *
 * Used only when `-Ddirect_kernel=true` is passed to `zig build`.
 * Produces an ELF that QEMU `-kernel` can load directly: a small
 * boot-time section at a low physical address (the QEMU virt machine's
 * standard kernel load offset 0x40000000 + 0x80000) followed by the
 * regular kernel image linked at its usual high virtual address.
 *
 * LMAs (physical addresses, what QEMU actually writes to RAM) are all
 * in the 0x40080000+ range so QEMU's direct-kernel loader can place
 * the segments. VMAs are:
 *
 *   - .text.boot  → identity mapped (VMA = LMA), because _start runs
 *                   with the MMU off and any PC-relative or literal-
 *                   pool load must resolve to the physical address.
 *   - .text/.rodata/.data/.bss → high kernel VA (0xFFFF000000000000+),
 *                   the same base the rest of the kernel code and
 *                   the UEFI boot path already use, so all references
 *                   between Zig files keep working once Phase 2 has
 *                   brought up the kernel page tables.
 *
 * KASLR: the UEFI path applies a runtime KASLR slide via the
 * bootloader's ELF loader. The direct-kernel path here does NOT slide,
 * so every VMA in `.text` and friends is stable at the link-time base.
 * That's fine for the dev-only TCG loop this mode targets; when we
 * eventually ship direct-kernel for bare-metal Pi 5 we can layer KASLR
 * on top by making the boot stub pick a slide and patch the page
 * tables before calling into Zig.
 */

ENTRY(_start)

KERNEL_VADDR_BASE = 0xFFFF000000000000;
BOOT_PADDR_BASE   = 0x40080000;

SECTIONS {
    . = BOOT_PADDR_BASE;

    /* Boot stub: entered by QEMU -kernel with MMU off. Must be
     * position-stable at its LMA. _start lives here, along with any
     * future low-PA helpers needed before the page tables come up. */
    .text.boot ALIGN(4K) : {
        KEEP(*(.text._start))
        *(.text.boot*)
    } :boot

    /* Boot-time data: bootstrap stack + initial page tables + any
     * other low-PA storage touched before TTBR1 is set up. Shares the
     * same `boot` PT_LOAD as .text.boot because the MMU is off while
     * we execute from it — the PHDR's uniform RWX permissions are
     * irrelevant to the hardware protection at that point. */
    .data.boot ALIGN(4K) : {
        *(.data.boot*)
    } :boot

    _boot_end_lma = .;

    /* Kernel image: linked at high VA, LMA continues right after the
     * boot stub so QEMU loads everything in one contiguous blob. */
    . = KERNEL_VADDR_BASE;

    .text ALIGN(4K) : AT(_boot_end_lma) {
        *(.text*)
    } :kernel

    .rodata ALIGN(4K) : {
        *(.rodata*)
    } :kernel

    .data ALIGN(4K) : {
        *(.data*)
    } :kernel

    .bss (NOLOAD) : ALIGN(4K) {
        *(COMMON)
        *(.bss*)
    } :kernel

    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) *(.debug*) }
}

PHDRS {
    boot   PT_LOAD FLAGS(7); /* R + W + X — MMU is off while executing from here */
    kernel PT_LOAD FLAGS(7); /* R + W + X — single PT_LOAD for all kernel sections */
}
