// aarch64 EL2 probe — standalone binary for `qemu-system-aarch64 -kernel`.
//
// Motivation:
//   The Zag aarch64 kernel currently boots via AAVMF UEFI, which drops to
//   EL1 before our code runs and (on Debian/Ubuntu's AAVMF build) crashes
//   outright when `-machine virt,virtualization=on` is set. Since EL2 is a
//   prerequisite for the KVM object layer (stage-2 translation, HCR_EL2,
//   VTTBR_EL2, ERET-into-guest), we need a different entry mechanism.
//
//   QEMU's direct-kernel boot for aarch64 (`-kernel file.elf` on `-M virt`)
//   bypasses firmware entirely and drops us at:
//     * EL2 when `virtualization=on` is set
//     * EL1 otherwise
//   with x0 = DTB physical address, MMU off, caches off, SP undefined.
//
//   This probe is the minimal proof — it reads CurrentEL and ID_AA64PFR0_EL1,
//   prints both as hex over the PL011 UART at 0x09000000, then halts. It is
//   intentionally standalone (no Zag dependencies) so the entire pipeline
//   from ELF loading through UART write can be validated in isolation.
//
//   Build:
//     zig cc -target aarch64-freestanding -nostdlib -ffreestanding \
//       -c kernel/arch/aarch64/boot/el2_probe.S -o probe.o
//     zig cc -target aarch64-freestanding -nostdlib -ffreestanding \
//       -Wl,-T,kernel/arch/aarch64/boot/el2_probe.ld probe.o -o probe.elf
//
//   Run:
//     qemu-system-aarch64 -M virt,gic-version=3,virtualization=on \
//       -cpu cortex-a72 -m 1G -nographic -no-reboot -kernel probe.elf
//
//   Expected output at EL2:
//     EL=0000000000000008 PFR0=0000000001000222
//   (CurrentEL=0x8 → M[3:2]=0b10 → EL2; PFR0[11:8]=2 → EL2 implemented)
//
//   This probe is the seed of the real aarch64 boot path — the next step
//   is to extend it into a proper `_start` that sets up a bootstrap stack,
//   parses the DTB for memory regions, synthesizes a BootInfo struct, and
//   jumps to `kEntry`. See task #82.
//
// References:
//   - ARM ARM D13.2.25  CurrentEL
//   - ARM ARM D13.2.66  ID_AA64PFR0_EL1
//   - QEMU docs/system/arm/virt.rst  "Boot options"

    .section .text._start,"ax",%progbits
    .global _start
_start:
    // Bootstrap stack inside our own image (see el2_probe.ld).
    adrp    x1, stack_top
    add     x1, x1, :lo12:stack_top
    mov     sp, x1

    mrs     x19, CurrentEL
    mrs     x20, id_aa64pfr0_el1

    mov     w0, 'E'
    bl      putc
    mov     w0, 'L'
    bl      putc
    mov     w0, '='
    bl      putc
    mov     x0, x19
    bl      puthex64

    mov     w0, ' '
    bl      putc
    mov     w0, 'P'
    bl      putc
    mov     w0, 'F'
    bl      putc
    mov     w0, 'R'
    bl      putc
    mov     w0, '0'
    bl      putc
    mov     w0, '='
    bl      putc
    mov     x0, x20
    bl      puthex64
    mov     w0, '\n'
    bl      putc

halt:
    wfe
    b       halt

// putc: w0 = byte. Writes to PL011 DR at 0x09000000.
// ARM PL011 DDI 0183: DR is at offset 0; at reset the UART accepts
// writes without any prior FCR/LCR/CR programming on QEMU's model.
putc:
    mov     x1, #0x09000000
    strb    w0, [x1]
    ret

// puthex64: x0 = value. 16 hex chars, most-significant nibble first.
puthex64:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    str     x19, [sp, #16]
    str     x20, [sp, #24]
    mov     x19, x0
    mov     x20, #60
1:  lsr     x0, x19, x20
    and     x0, x0, #0xF
    cmp     x0, #10
    blt     2f
    add     x0, x0, #('A' - 10)
    b       3f
2:  add     x0, x0, #'0'
3:  bl      putc
    subs    x20, x20, #4
    bge     1b
    ldr     x19, [sp, #16]
    ldr     x20, [sp, #24]
    ldp     x29, x30, [sp], #32
    ret

    .section .bss.stack,"aw",%nobits
    .balign 16
    .space 4096
stack_top:
