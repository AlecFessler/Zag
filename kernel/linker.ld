ENTRY(_start)

KERNEL_VADDR_BASE = 0xFFFFFFFF80000000;

SECTIONS {
    . = KERNEL_VADDR_BASE;

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
