ENTRY(_start)

KERNEL_VADDR_BASE = 0xFFFFFFFF80000000;
STACK_SIZE = 0x4000;

SECTIONS {
    . = KERNEL_VADDR_BASE;

    .text : ALIGN(4K) {
        *(.text*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata*)
        PROVIDE(_kernel_base_vaddr = KERNEL_VADDR_BASE);
    }

    .data : ALIGN(4K) {
        *(.data*)
    }

    .bss (NOLOAD) : ALIGN(4K) {
        *(COMMON)
        *(.bss*)
    }

    __stackguard_upper (NOLOAD) : ALIGN(4K) {
        . += 4K;
    } :__stackguard_upper

    __stack (NOLOAD) : ALIGN(4K) {
        . += STACK_SIZE;
    } :__stack

    __stackguard_lower (NOLOAD) : ALIGN(4K) {
        PROVIDE(__stackguard_lower = .);
        . += 4K;
    } :__stackguard_lower
}
