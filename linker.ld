ENTRY(_start)

KERNEL_VMA = 0xFFFFFFFF80000000;
KERNEL_LMA = 0x00100000;

SECTIONS {
    . = KERNEL_LMA;
    .boot.text : ALIGN(4K) {
        KEEP(*(.multiboot))
        *(.boot.text*)
    }

    .boot.rodata : ALIGN(4K) {
        *(.boot.rodata*)
    }

    .boot.data : ALIGN(4K) {
        *(.boot.data*)
    }

    __boot_load_end = LOADADDR(.boot.data) + SIZEOF(.boot.data);
    PHYS_OFFSET = __boot_load_end - KERNEL_VMA;

    .boot.bss (NOLOAD) : AT(0) ALIGN(4K) {
        *(.boot.bss*)
    }

    . = KERNEL_VMA;

    .text : AT(ADDR(.text) + PHYS_OFFSET) ALIGN(4K) {
        *(.text*)
    }

    .rodata : AT(ADDR(.rodata) + PHYS_OFFSET) ALIGN(4K) {
        *(.rodata*)
    }

    .data : AT(ADDR(.data) + PHYS_OFFSET) ALIGN(4K) {
        *(.data*)
    }

    .bss (NOLOAD) : AT(ADDR(.bss) + PHYS_OFFSET) ALIGN(4K) {
        *(COMMON)
        *(.bss*)
        PROVIDE(_kernel_end = .);
    }
}
