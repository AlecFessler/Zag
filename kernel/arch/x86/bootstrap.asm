[BITS 32]

global _start

MBALIGN    equ 1 << 0                ; align loaded modules to page boundaries
MEMINFO    equ 1 << 1                ; provide memory map
MBFLAGS    equ MBALIGN | MEMINFO     ; multiboot header flags
MAGIC      equ 0x1BADB002            ; multiboot header magic number
MBCHECKSUM equ -(MAGIC + MBFLAGS)    ; multiboot checksum

PAGE_P     equ 1
PAGE_RW    equ 2
PAGE_LG    equ (1 << 7)              ; 2 MiB page bit in PDE
PAGEFLAGS  equ (PAGE_P | PAGE_RW)

section .multiboot
align 4
    dd MAGIC
    dd MBFLAGS
    dd MBCHECKSUM

section .boot.text
_start:
    cli

    mov [saved_mb_magic], eax
    mov [saved_mb_info], ebx

    lgdt [gdt_descriptor]

    mov eax, cr4
    or eax, 1 << 5                  ; set physical address extension bit (PAE)
    mov cr4, eax

    mov eax, pml4
    mov cr3, eax                    ; store page map level 4 into control register 3

    mov ecx, 0xC0000080             ; load extended feature enable register (EFER)
    rdmsr                           ; read model specific register
    or eax, (1 << 8) | (1 << 11)    ; set long mode enable (LME) and no execute enable (NXE)
    wrmsr                           ; write model specific register

    mov eax, cr0
    ; set paging enable (PG), write protection (WP), and protection enable (PE) bits
    or eax, (1 << 0) | (1 << 16) | (1 << 31)
    mov cr0, eax                    ; next instruction fetch enters long mode

    jmp 0x08:long_mode_stub         ; reload code segment

section .boot.data
saved_mb_magic:
    dd 0

saved_mb_info:
    dd 0

gdt:                                ; global descriptor table
    dq 0x0000000000000000           ; null descriptor
    dq 0x00AF9A000000FFFF           ; 64-bit code segment 0x08
    dq 0x00AF92000000FFFF           ; 64-bit data segment 0x10
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt - 1
    dd gdt

align 4096
pml4:
    dq pdpt + PAGEFLAGS
    times 510 dq 0
    dq pdpt + PAGEFLAGS

align 4096
pdpt:
    dq pd + PAGEFLAGS
    times 509 dq 0
    dq pd + PAGEFLAGS
    dq 0

align 4096
pd:
    dq 0x00000000 | PAGEFLAGS | PAGE_LG
    dq 0x00200000 | PAGEFLAGS | PAGE_LG
    dq 0x00400000 | PAGEFLAGS | PAGE_LG
    times 509 dq 0

[BITS 64]
section .boot.stub.text
long_mode_stub:
    mov rax, long_mode_entry
    jmp rax

section .bss nobits
align 16
resb 16384
stack_top:

section .text
extern kmain

long_mode_entry:
    mov ax, 0x10                  ; data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, stack_top

    mov rdi, stack_top
    mov esi, dword [saved_mb_magic]
    mov edx, dword [saved_mb_info]

    mov qword [pml4], 0
    mov rax, cr3
    mov cr3, rax

    call kmain

.hang:
    hlt
    jmp .hang
