ENTRY(_start)

KERNEL_VADDR_BASE = 0xFFFF000000000000;

SECTIONS {
    . = KERNEL_VADDR_BASE;

    /*
     * EL2 hyp text — kernel's EL2 vector table + HVC dispatcher + world
     * switch helpers. Forced into a single 4 KiB-aligned region so every
     * PC-relative branch inside this region (notably `b hyp_sync_lower_a64`
     * from `__hyp_vectors` offset 0x400, and branches out of the dispatcher
     * to the per-HVC handlers) lands on a PA that stays consistent with
     * its link-time VA offset when the page is allocated as a single
     * RuntimeServicesCode page and VBAR_EL2 is programmed with its PA.
     *
     * The whole range must fit in a single 4 KiB page (0x1000 bytes)
     * because the bootloader allocates code pages individually and
     * AAVMF's post-ExitBootServices EL2 mapping only guarantees execute
     * permission on `runtime_services_code` pages. Crossing a page
     * boundary would make any cross-page PC-relative branch land on a
     * non-contiguous PA and fault with IFSC=0xF.
     */
    .hyp_text : ALIGN(4K) {
        KEEP(*(.hyp_vectors))
        KEEP(*(.hyp_text))
        . = ALIGN(4K);
    }

    .text : ALIGN(4K) {
        *(.text*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata*)
    }

    .data : ALIGN(4K) {
        *(.data*)
    }

    .bss (NOLOAD) : ALIGN(4K) {
        *(COMMON)
        *(.bss*)
    }
}
