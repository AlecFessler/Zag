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

    mov edi, eax                    ; save magic
    mov esi, ebx                    ; save multiboot info

    xor eax, eax
    mov esp, boot_stack_top

    lgdt [gdt_descriptor]           ; already physical base for gdt descriptor

    mov eax, cr4
    or eax, 1 << 5                  ; set physical address extension bit (PAE)
    mov cr4, eax

    mov eax, pml4                   ; use physical address of pml4
    mov cr3, eax                    ; store page map level 4 into control register 3

    mov ecx, 0xC0000080             ; load extended feature enable register (EFER)
    rdmsr                           ; read model specific register
    or eax, 1 << 8                  ; set long mode enable (LME)
    wrmsr                           ; write model specific register

    mov eax, cr0
    or eax, (1 << 0) | (1 << 31)    ; set paging enable (PG) and protection enable (PE) bits
    mov cr0, eax                    ; next instruction fetch enters long mode

    jmp 0x08:long_mode_stub         ; reload code segment


section .boot.data
gdt:                                ; global descriptor table
    dq 0x0000000000000000           ; null descriptor
    dq 0x00AF9A000000FFFF           ; 64-bit code segment 0x08
    dq 0x00AF92000000FFFF           ; 64-bit data segment 0x10
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt - 1            ; gdt size
    dd gdt

align 4096
pml4:                              ; page map level 4
    dq pdpt_low + PAGEFLAGS        ; pml4[0] lower half
    times 510 dq 0                 ; zero up to index 510
    dq pdpt_high + PAGEFLAGS       ; pml4[511] higher half

align 4096
pdpt_low:                          ; page directory pointer table
    dq pd_low + PAGEFLAGS
    times 511 dq 0

align 4096
pdpt_high:                         ; page directory pointer table
    times 510 dq 0
    dq pd_high + PAGEFLAGS
    dq 0

align 4096
pd_low:                            ; page directory
    dq 0 | PAGEFLAGS | PAGE_LG
    times 511 dq 0

align 4096
pd_high:                           ; page directory
    dq 0 | PAGEFLAGS | PAGE_LG
    times 511 dq 0

section .boot.bss nobits
align 16
resb 16384
boot_stack_top:

[BITS 64]
section .boot.text
long_mode_stub:
    mov ax, 0x10                  ; data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rax, long_mode_entry
    jmp rax

section .bss nobits
align 16
resb 16384
hh_stack_top:

section .text
extern kmain

long_mode_entry:
    mov ax, 0x10                  ; data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, hh_stack_top

    ; zero out the identity mapped page and invalidate it in the tlb
    mov rax, pd_low
    mov qword [rax], 0
    invlpg [0]

    ; multiboot magic and info should still be in edi and esi unless something clobbers them
    call kmain

.hang:
    hlt
    jmp .hang
