[BITS 32]
global _start

MBALIGN    equ 1 << 0                ; align loaded modules to page boundaries
MEMINFO    equ 1 << 1                ; provide memory map
MBFLAGS    equ MBALIGN | MEMINFO     ; multiboot header flags
MAGIC      equ 0x1BADB002            ; multiboot header magic number
MBCHECKSUM equ -(MAGIC + MBFLAGS)    ; multiboot checksum

PAGEFLAGS  equ 0x03

section .multiboot
align 4
    dd MAGIC
    dd MBFLAGS
    dd MBCHECKSUM

section .text
_start:
    cli
    xor eax, eax
    mov esp, stack_top

    lgdt [gdt_descriptor]

    mov eax, cr4
    or eax, 1 << 5                ; set physical address extension bit (PAE)
    mov cr4, eax

    mov eax, pml4
    mov cr3, eax                  ; store page map level 4 into control register 3

    mov ecx, 0xC0000080           ; load extended feature enable register (EFER)
    rdmsr                         ; read model specific register
    or eax, 1 << 8                ; set long mode enable (LME)
    wrmsr                         ; write model specific register

    mov eax, cr0
    or eax, (1 << 0) | (1 << 31)  ; set paging enable (PG) and protection enable (PE) bits
    mov cr0, eax                  ; next instruction fetch enters long mode

    jmp 0x08:long_mode_entry      ; reload code segment

section .data
gdt:                              ; global descriptor table
    dq 0x0000000000000000         ; null descriptor
    dq 0x00AF9B000000FFFF         ; 64-bit code segment 0x08
    dq 0x00AF93000000FFFF         ; 64-bit data segment 0x10
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt - 1          ; gdt size
    dd gdt

align 4096
pml4:                             ; page map level 4
    dq pdpt + PAGEFLAGS           ; Present | Writable

align 4096
pdpt:                             ; page directory pointer table
    dq pd + PAGEFLAGS             ; Present | Writable

align 4096
pd:                               ; page directory
    dq 0x00000083                 ; Present | Writable | 2 MiB page

section .bss
align 16
resb 16384
stack_top:

[BITS 64]
section .text
long_mode_entry:
    mov ax, 0x10                  ; data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, stack_top

    extern kmain
    call kmain

.hang:
    hlt
    jmp .hang
