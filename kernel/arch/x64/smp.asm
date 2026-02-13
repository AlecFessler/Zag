; AP Trampoline
; Assembled as flat binary, copied to 0x8000 at runtime

[org 0x8000]

; ─── 16-bit real mode ─────────────────────────────────────────────
[bits 16]
trampoline_start:
    cli
    cld
    mov al, 'T'
    mov dx, 0x3F8
    out dx, al

    ; set up segments for real mode
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; load temporary GDT
    lgdt [gdt_ptr]

    ; enable protected mode (CR0.PE)
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; far jump to flush pipeline and load 32-bit CS
    jmp 0x08:.protected_mode

; ─── 32-bit protected mode ────────────────────────────────────────
[bits 32]
.protected_mode:
    ; load data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; enable PAE (CR4.PAE, bit 5)
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    ; load page table root from parameter block
    mov eax, [params.cr3]
    mov cr3, eax

    ; enable long mode (EFER.LME, bit 8)
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    ; enable long mode AND NXE (EFER.LME bit 8, EFER.NXE bit 11)
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr

    ; enable paging (CR0.PG, bit 31)
    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    ; far jump to 64-bit code segment
    jmp 0x18:.long_mode

; ─── 64-bit long mode ─────────────────────────────────────────────
[bits 64]
.long_mode:
    ; load stack pointer from parameter block
    mov rsp, [params.stack_top]

    ; load entry point and jump
    mov rax, [params.entry_point]
    jmp rax

; ─── temporary GDT ────────────────────────────────────────────────
align 16
gdt:
    ; null descriptor
    dq 0x0000000000000000
    ; 32-bit code segment (selector 0x08)
    dq 0x00CF9A000000FFFF
    ; 32-bit data segment (selector 0x10)
    dq 0x00CF92000000FFFF
    ; 64-bit code segment (selector 0x18)
    dq 0x00AF9A000000FFFF
gdt_end:

gdt_ptr:
    dw gdt_end - gdt - 1
    dd gdt

; ─── parameter block (written by BSP before SIPI) ────────────────
align 8
params:
.cr3:         dq 0
.stack_top:   dq 0
.entry_point: dq 0

trampoline_end:
