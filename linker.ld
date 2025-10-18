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
        PROVIDE(_text_start = .);
        *(.text*)
        PROVIDE(_text_end = .);
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VMA) ALIGN(4K) {
        PROVIDE(_rodata_start = .);
        *(.rodata*)
        PROVIDE(_rodata_end = .);
    }

    .data : AT(ADDR(.data) - KERNEL_VMA) ALIGN(4K) {
        PROVIDE(_data_start = .);
        *(.data*)
        PROVIDE(_data_end = .);
    }

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_VMA) ALIGN(4K) {
        PROVIDE(_bss_start = .);
        *(COMMON)
        *(.bss*)
        PROVIDE(_bss_end = .);
        PROVIDE(_kernel_end = .);
        PROVIDE(_kernel_base_vaddr = KERNEL_VMA);
    }
}
