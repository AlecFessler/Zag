ENTRY(_start)

BOOT_LMA = 0x00100000;

KERNEL_VMA = 0xFFFFFFFF80000000;
KERNEL_LMA = 0x00200000;
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

    . = KERNEL_VMA;
    __load_offset = KERNEL_LMA;

    .text : AT(__load_offset) ALIGN(4K) {
        *(.text*)
    }
    __load_offset += SIZEOF(.text);

    .rodata : AT(__load_offset) ALIGN(4K) {
        *(.rodata*)
    }
    __load_offset += SIZEOF(.rodata);

    .eh_frame_hdr : AT(__load_offset) ALIGN(4) {
        *(.eh_frame_hdr) *(.eh_frame_hdr.*)
    }
    __load_offset += SIZEOF(.eh_frame_hdr);

    .eh_frame : AT(__load_offset) ALIGN(8) {
        KEEP(*(.eh_frame)) *(.eh_frame.*)
    }
    __load_offset += SIZEOF(.eh_frame);

    .data : AT(__load_offset) ALIGN(4K) {
        *(.data*)
    }
    __load_offset += SIZEOF(.data);

    .bss (NOLOAD) : AT(__load_offset) ALIGN(4K) {
        *(COMMON)
        *(.bss*)
        PROVIDE(_kernel_end = .);
    }
}
