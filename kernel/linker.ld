ENTRY(_start)

KERNEL_VADDR_BASE = 0xFFFFFFFF80000000;
KERNEL_VADDR_TEXT = 0xFFFFFFFF80100000;
STACK_SIZE = 0x4000;

SECTIONS {
    . = KERNEL_VADDR_TEXT;

    .text : AT(ADDR(.text) - KERNEL_VADDR_BASE) ALIGN(4K) {
        *(.text*)
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VADDR_BASE) ALIGN(4K) {
        *(.rodata*)
        PROVIDE(_kernel_base_vaddr = KERNEL_VADDR_BASE);
    }

    .data : AT(ADDR(.data) - KERNEL_VADDR_BASE) ALIGN(4K) {
        *(.data*)
    }

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VADDR_BASE) ALIGN(4K) {
        *(COMMON)
        *(.bss*)
    }

    __stackguard_upper ALIGN(4K) (NOLOAD) : AT (ADDR(__stackguard_upper) - KERNEL_VADDR_BASE) {
        . += 4K;
    } :__stackguard_upper

    __stack ALIGN(4K) (NOLOAD) : AT (ADDR(__stack) - KERNEL_VADDR_BASE) {
        . += STACK_SIZE;
    } :__stack

    __stackguard_lower ALIGN(4K) (NOLOAD) : AT (ADDR(__stackguard_lower) - KERNEL_VADDR_BASE) {
        PROVIDE(__stackguard_lower = .);
        . += 4K;
    } :__stackguard_lower
}
