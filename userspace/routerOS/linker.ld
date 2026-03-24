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
    .data : {
        *(.data .data.*)
        /* BSS merged into data: demand-paging of BSS has a kernel bug where
           adjacent VMM nodes at exact page boundaries can't be found by
           findNodeLocked. Additionally, undefined globals in BSS may contain
           garbage pointers that cause wild dereferences before initialization.
           Merging BSS into data ensures all pages are eagerly allocated and
           zero-initialized by the ELF loader. */
        *(.bss .bss.*)
    }

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
