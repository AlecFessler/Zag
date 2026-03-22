ENTRY(_start)

SECTIONS {
    . = 0x0;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : { *(.rodata .rodata.*) }
    .rela.dyn : { *(.rela.dyn) *(.rela.*) }
    .got : { *(.got) *(.got.plt) }
    .data : { *(.data .data.*) }
    .bss : { *(.bss .bss.*) }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.gnu.hash)
    }
}
