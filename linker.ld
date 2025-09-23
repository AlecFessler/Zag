ENTRY(_start)

BOOT_LMA = 0x00100000;
KERNEL_LMA = 0x00200000;
KERNEL_VMA = 0xFFFFFFFF80000000;

SECTIONS {
    . = BOOT_LMA;
    .boot.text : ALIGN(4K) {
        KEEP(*(.multiboot))
        *(.boot.text*)
    }

    .boot.stub.text : ALIGN(4K) {
        KEEP(*(.boot.stub.text*))
    }

    .boot.rodata : ALIGN(4K) {
        *(.boot.rodata*)
    }

    .boot.data : ALIGN(4K) {
        *(.boot.data*)
    }

    . = KERNEL_VMA + KERNEL_LMA;

    .text : AT(ADDR(.text) - KERNEL_VMA) ALIGN(4K) {
        *(.text*)
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VMA) ALIGN(4K) {
        *(.rodata*)
    }

    .data : AT(ADDR(.data) - KERNEL_VMA) ALIGN(4K) {
        *(.data*)
    }

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VMA) ALIGN(4K) {
        *(COMMON)
        *(.bss*)
        PROVIDE(_kernel_end = .);
        PROVIDE(_kernel_vma = KERNEL_VMA);
    }
}
