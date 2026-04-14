// aarch64 direct-kernel boot entry.
//
// Linked into the kernel only when `-Ddirect_kernel=true`. In that mode
// QEMU (`-M virt,virtualization=on -kernel`) loads the ELF directly and
// jumps here at EL2 with x0 = DTB phys, MMU off. The regular UEFI path
// (`kEntry` symbol) still works for builds that omit this file.
//
// Boot phases:
//
//   Phase 1 (history): minimal print-and-halt from EL2.
//
//   Phase 2 (history): programmed MMU + 16 MiB identity map, dropped to
//                      EL1 through ERET, proved translation works,
//                      halted at a landing pad.
//
//   Phase 3 (this file): full TTBR0 identity (1 GiB block) + TTBR1 high-
//                        VA kernel image map (8 × 2 MiB blocks), then
//                        branch to Zig helper `directKernelEntry` at the
//                        kernel's high VA, which synthesises BootInfo
//                        and tail-calls `kEntry`. From there the kernel
//                        boots the same way it does under UEFI.
//
// Memory layout (direct-kernel, -m 1G, virt):
//
//   PA 0x09000000            PL011 UART (Device-nGnRnE)
//   PA 0x40000000..0x80000000  1 GiB of RAM
//   PA 0x40080000..0x40200000  boot PT_LOAD (stub + page tables + stack)
//   PA 0x40200000..            kernel PT_LOAD (text/rodata/data/bss)
//   VA 0xFFFF000000000000..    kernel image (TTBR1, 8 × 2 MiB blocks)
//
// Page tables built here (all 4 KiB, in .data.boot):
//
//   TTBR0 (low-VA identity):
//     __ttbr0_l0[0] → __ttbr0_l1
//     __ttbr0_l1[0] → __ttbr0_l2_dev   (0x00000000..0x40000000, for PL011)
//     __ttbr0_l1[1] = 1 GiB block → PA 0x40000000 (all of RAM)
//     __ttbr0_l2_dev[72] = 2 MiB device block for PL011 at 0x09000000
//
//   TTBR1 (high-VA kernel image):
//     __ttbr1_l0[0]  → __ttbr1_l1
//     __ttbr1_l1[0]  → __ttbr1_l2
//     __ttbr1_l2[0..7] = 2 MiB Normal-WB blocks → PA 0x40200000..0x41200000
//
// Markers on the PL011 UART (single-char each; a healthy boot prints
// "3M K T M m ..." — the lowercase letters come from kMain's own early
// debug chars once control reaches high-VA kernel code):
//
//   '3' — EL2 entry reached in Phase 3 (stack valid)
//   'M' — EL1 MMU sysregs programmed, about to ERET
//
// References:
//   ARM ARM D5.3.3   VMSAv8-64 block/table descriptor encoding
//   ARM ARM D13.2.*  HCR_EL2 / CPTR_EL2 / MAIR_EL1 / TCR_EL1 / SCTLR_EL1
//   QEMU docs/system/arm/virt.rst — direct-kernel boot ABI

    .section .text.boot,"ax",%progbits
    .global _start
_start:
    // UEFI-path detector: if we were entered at EL1 (i.e. a UEFI-loaded
    // build that happens to have this file linked in), tail-call kEntry
    // so nothing about the UEFI flow changes. Direct-kernel enters at
    // EL2 and falls through.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #1
    b.eq    el1_uefi_entry

    // Direct-kernel EL2 entry. Save DTB; bring up bootstrap stack.
    mov     x19, x0
    adrp    x9, __boot_stack_top
    add     x9, x9, :lo12:__boot_stack_top
    mov     sp, x9

    mov     w0, #'3'
    bl      uart_putc

    // HCR_EL2.RW = 1: EL1 executes AArch64. Everything else left at
    // reset-default zero; KVM vmResume will flip per-guest bits later.
    mov     x9, #1
    lsl     x9, x9, #31
    msr     hcr_el2, x9
    isb

    // CPTR_EL2: don't trap FP/SIMD to EL2. Matches Linux arm64 head.S.
    mov     x9, #0x33FF
    msr     cptr_el2, x9
    isb

    // CPACR_EL1.FPEN = 11: don't trap EL0/EL1 FP/SIMD to EL1. Without
    // this, the first FP/SIMD instruction emitted by the Zig compiler
    // inside `directKernelEntry` (struct copy, register spill, etc.)
    // raises a synchronous EC=0x07 trap and we never reach kEntry.
    mov     x9, #(0b11 << 20)
    msr     cpacr_el1, x9
    isb

    // MAIR_EL1: index 0 = Normal WB, index 1 = Device-nGnRnE, all others 0.
    ldr     x9, =0x00000000000000FF
    msr     mair_el1, x9

    // TCR_EL1: 4K granule, T0SZ=T1SZ=16, IS shareable, WB walks, IPS=40.
    ldr     x9, =0x00000002B5103510
    msr     tcr_el1, x9

    bl      zero_boot_pagetables
    bl      build_ttbr0_identity
    bl      build_ttbr1_kernel

    // TTBR0 = low-VA identity root; TTBR1 = high-VA kernel image root.
    adrp    x9, __ttbr0_l0
    add     x9, x9, :lo12:__ttbr0_l0
    msr     ttbr0_el1, x9
    adrp    x9, __ttbr1_l0
    add     x9, x9, :lo12:__ttbr1_l0
    msr     ttbr1_el1, x9

    dsb     ishst
    isb

    // Install a diagnostic VBAR_EL1 so any EL1 fault lands in our
    // print-and-halt stub instead of looping in page-faulted vectors.
    adrp    x9, __diag_vectors
    add     x9, x9, :lo12:__diag_vectors
    msr     vbar_el1, x9
    isb

    // Install the EL2 hyp stub vector table so HVC from EL1 reaches a
    // real handler. Runs with SCTLR_EL2.M=0 (EL2 MMU off), so the
    // vector PAs come from adrp against the kernel LMA in .text.boot.
    // Until the world-switch path lands, the HVC handler is a trivial
    // ERET back to EL1 so we can smoke-test that the hyp stub round-
    // trips without touching guest state.
    adrp    x9, __hyp_vectors
    add     x9, x9, :lo12:__hyp_vectors
    msr     vbar_el2, x9
    isb

    // Enable EL1 MMU + D-cache + I-cache. SCTLR_EL1 RES1 bits preserved.
    mrs     x9, sctlr_el1
    orr     x9, x9, #(1 << 0)
    orr     x9, x9, #(1 << 2)
    orr     x9, x9, #(1 << 12)
    msr     sctlr_el1, x9
    dsb     ish
    isb

    mov     w0, #'M'
    bl      uart_putc

    // ERET into the low-VA landing pad. From there we'll branch to the
    // high-VA Zig entry point, which lives in .text of the kernel image
    // and is reachable because TTBR1 now covers it.
    adrp    x9, phase3_el1_trampoline
    add     x9, x9, :lo12:phase3_el1_trampoline
    msr     elr_el2, x9
    mov     x9, #0x3C5
    msr     spsr_el2, x9
    mov     x0, x19
    eret

// -----------------------------------------------------------------
// UEFI fallback entry. Tail-calls kEntry(BootInfo*).
// -----------------------------------------------------------------
el1_uefi_entry:
    ldr     x9, =kEntry
    br      x9

// -----------------------------------------------------------------
// Phase-3 EL1 trampoline. Still in the low-PA identity region; hops
// to the high-VA Zig entry. SP is reloaded because exception return
// switches to SP_EL1 which wasn't initialised at the EL2 side.
// -----------------------------------------------------------------
phase3_el1_trampoline:
    adrp    x9, __boot_stack_top
    add     x9, x9, :lo12:__boot_stack_top
    mov     sp, x9
    // Marker 'E' — post-ERET, low-VA code running with MMU on.
    mov     x19, x0            // preserve DTB while we clobber x0 for putc
    mov     w0, #'E'
    bl      uart_putc
    // Marker 'H' — about to branch to high-VA Zig entry.
    mov     w0, #'H'
    bl      uart_putc
    mov     x0, x19
    // Hand off to Zig via the C ABI. The symbol resolves through the
    // literal pool at link time; its value is a high VA that requires
    // TTBR1 + kernel block descriptors to be live.
    ldr     x9, =directKernelEntry
    br      x9

// -----------------------------------------------------------------
// Helpers (run MMU-off at EL2, must stay in .text.boot).
// -----------------------------------------------------------------

// w0 = byte. PL011 DR is raw-writable after reset in QEMU virt.
uart_putc:
    ldr     x1, =0x09000000
    strb    w0, [x1]
    ret

// Print a 16-nibble hex value in x0. Clobbers x0..x3.
uart_puthex:
    mov     x3, x0
    mov     x2, #16
1:  lsr     x0, x3, #60             // top nibble
    and     x0, x0, #0xF
    cmp     x0, #10
    b.lt    2f
    add     x0, x0, #('A' - 10)
    b       3f
2:  add     x0, x0, #'0'
3:  ldr     x1, =0x09000000
    strb    w0, [x1]
    lsl     x3, x3, #4
    subs    x2, x2, #1
    b.ne    1b
    ret

// Diagnostic EL1 vector table. Only the sync-from-same-EL-SP_ELx
// handler (+0x200) is populated; everything else halts silently.
// Prints 'F', ESR_EL1, ':', FAR_EL1, newline, then WFEs forever. A
// page fault mid-transition now shows up as a single line in the
// serial tail instead of an infinite exception loop.
    .balign 2048
__diag_vectors:
    .org __diag_vectors + 0x000
    b       diag_halt                   // sync EL1t
    .org __diag_vectors + 0x080
    b       diag_halt                   // irq EL1t
    .org __diag_vectors + 0x100
    b       diag_halt                   // fiq EL1t
    .org __diag_vectors + 0x180
    b       diag_halt                   // serror EL1t
    .org __diag_vectors + 0x200
    b       diag_fault                  // sync EL1h
    .org __diag_vectors + 0x280
    b       diag_halt                   // irq EL1h
    .org __diag_vectors + 0x300
    b       diag_halt                   // fiq EL1h
    .org __diag_vectors + 0x380
    b       diag_halt                   // serror EL1h
    .org __diag_vectors + 0x400
    b       diag_halt                   // sync lower EL aarch64
    .org __diag_vectors + 0x480
    b       diag_halt
    .org __diag_vectors + 0x500
    b       diag_halt
    .org __diag_vectors + 0x580
    b       diag_halt
    .org __diag_vectors + 0x600
    b       diag_halt
    .org __diag_vectors + 0x680
    b       diag_halt
    .org __diag_vectors + 0x700
    b       diag_halt
    .org __diag_vectors + 0x780
    b       diag_halt

diag_fault:
    mov     w0, #'F'
    bl      uart_putc
    mrs     x0, esr_el1
    bl      uart_puthex
    mov     w0, #':'
    bl      uart_putc
    mrs     x0, far_el1
    bl      uart_puthex
    mov     w0, #'\n'
    bl      uart_putc
diag_halt:
1:  wfe
    b       1b

// -----------------------------------------------------------------
// EL2 hyp stub vectors. Runs with EL2 MMU off (SCTLR_EL2.M=0), so
// all code must be PA-addressable (.text.boot at its LMA in low RAM).
//
// Entry at +0x400 (sync from lower EL, AArch64) handles HVC from EL1.
// For the first increment this just ERETs back: HVC trap has already
// updated ELR_EL2 to the instruction after the HVC and SPSR_EL2 to
// the caller PSTATE, so a bare ERET returns control to EL1 at the
// next instruction. This lets the EL1 kernel smoke-test that the
// hyp stub is installed and the round-trip works without touching
// guest state.
//
// All other vectors halt: nothing else should ever trap to EL2 with
// our current HCR_EL2 (only RW=1 is set, no traps enabled). If one
// does, halt so we notice rather than silently ERETing.
    .balign 2048
__hyp_vectors:
    .org __hyp_vectors + 0x000
    b       hyp_halt                    // sync EL2t
    .org __hyp_vectors + 0x080
    b       hyp_halt                    // irq EL2t
    .org __hyp_vectors + 0x100
    b       hyp_halt                    // fiq EL2t
    .org __hyp_vectors + 0x180
    b       hyp_halt                    // serror EL2t
    .org __hyp_vectors + 0x200
    b       hyp_halt                    // sync EL2h
    .org __hyp_vectors + 0x280
    b       hyp_halt                    // irq EL2h
    .org __hyp_vectors + 0x300
    b       hyp_halt                    // fiq EL2h
    .org __hyp_vectors + 0x380
    b       hyp_halt                    // serror EL2h
    .org __hyp_vectors + 0x400
    b       hyp_sync_lower_a64          // sync lower EL A64 (HVC)
    .org __hyp_vectors + 0x480
    b       hyp_halt                    // irq lower EL A64
    .org __hyp_vectors + 0x500
    b       hyp_halt                    // fiq lower EL A64
    .org __hyp_vectors + 0x580
    b       hyp_halt                    // serror lower EL A64
    .org __hyp_vectors + 0x600
    b       hyp_halt
    .org __hyp_vectors + 0x680
    b       hyp_halt
    .org __hyp_vectors + 0x700
    b       hyp_halt
    .org __hyp_vectors + 0x780
    b       hyp_halt

hyp_sync_lower_a64:
    // ESR_EL2.EC == 0b010110 (HVC) is the only case we care about for
    // now. Unconditionally ERET so the kernel smoke test can confirm
    // the round-trip works. Later versions will decode ESR_EL2 here
    // and dispatch by hypercall id in x0.
    eret

hyp_halt:
1:  wfe
    b       1b

// Zero all six boot page tables (5 × 4 KiB for TTBR0+TTBR1 plus the
// device L2 table = 6 × 4 KiB = 24 KiB). Keeping them in a contiguous
// run in .data.boot lets this be a single linear sweep.
zero_boot_pagetables:
    adrp    x0, __boot_pagetables_start
    add     x0, x0, :lo12:__boot_pagetables_start
    mov     x1, #(6 * 4096)
1:  str     xzr, [x0], #8
    subs    x1, x1, #8
    b.ne    1b
    ret

// Build TTBR0 identity map:
//   L0[0] → L1
//   L1[0] → L2_dev       (VA 0x00000000..0x40000000, for PL011)
//   L1[1] = 1 GiB block  (VA 0x40000000..0x80000000 → PA 0x40000000)
//   L2_dev[72] = 2 MiB device block for PL011 @ 0x09000000
//
// Block encoding (ARM ARM D5.3.3):
//   Normal WB   low bits = 0x701 (at L1: block=bit1=0 → 0x701 with [1:0]=01)
//   Device      low bits = 0x705
//   Table desc  low bits = 0x003
//
// At L1 the "block" descriptor has [1:0]=01, giving 0x...701 when
// combined with the AttrIdx/AP/SH/AF bits. Same shape as the 2 MiB
// block at L2 — the block/table distinction is purely bit[1].
build_ttbr0_identity:
    // L2_dev[72]: PL011 device block.
    adrp    x0, __ttbr0_l2_dev
    add     x0, x0, :lo12:__ttbr0_l2_dev
    ldr     x1, =0x0000000009000000
    mov     x2, #0x705
    orr     x4, x1, x2
    str     x4, [x0, #(72 * 8)]

    // L1[0] → L2_dev (table descriptor).
    adrp    x0, __ttbr0_l1
    add     x0, x0, :lo12:__ttbr0_l1
    adrp    x1, __ttbr0_l2_dev
    add     x1, x1, :lo12:__ttbr0_l2_dev
    orr     x1, x1, #0x3
    str     x1, [x0, #0]

    // L1[1]: 1 GiB Normal-WB block mapping PA 0x40000000..0x80000000.
    // One block replaces the old L2_ram table; bump_allocator regions
    // beyond 16 MiB still resolve under the identity map this way.
    ldr     x1, =0x0000000040000000
    mov     x2, #0x701
    orr     x1, x1, x2
    str     x1, [x0, #8]

    // L0[0] → L1.
    adrp    x0, __ttbr0_l0
    add     x0, x0, :lo12:__ttbr0_l0
    adrp    x1, __ttbr0_l1
    add     x1, x1, :lo12:__ttbr0_l1
    orr     x1, x1, #0x3
    str     x1, [x0]

    dsb     ishst
    ret

// Build TTBR1 high-VA kernel image map:
//   L0[0] → L1
//   L1[0] → L2
//   L2[0..7] = 2 MiB Normal-WB blocks → PA 0x40200000..0x41200000
//
// This covers kernel .text + .rodata + .data + .bss up to 16 MiB. If
// the kernel image ever grows past that, bump the loop count here and
// in the linker pad. Our test builds are ~5 MiB currently, so 16 MiB
// is comfortable headroom.
//
// After memory.init() builds its physmap, TTBR1 gets populated with
// additional entries by mapPageBoot — those live at L0[511] (physmap
// VA 0xFFFF_FF80_0000_0000), which is a different L0 slot from this
// kernel_code mapping, so there's no conflict.
build_ttbr1_kernel:
    // L2[0..7]: eight 2 MiB blocks covering 16 MiB of kernel image.
    adrp    x0, __ttbr1_l2
    add     x0, x0, :lo12:__ttbr1_l2
    ldr     x1, =0x0000000040200000
    mov     x2, #0x701
    mov     x3, #8
1:  orr     x4, x1, x2
    str     x4, [x0], #8
    add     x1, x1, #0x200000
    subs    x3, x3, #1
    b.ne    1b

    // L1[0] → L2.
    adrp    x0, __ttbr1_l1
    add     x0, x0, :lo12:__ttbr1_l1
    adrp    x1, __ttbr1_l2
    add     x1, x1, :lo12:__ttbr1_l2
    orr     x1, x1, #0x3
    str     x1, [x0, #0]

    // L0[0] → L1.
    adrp    x0, __ttbr1_l0
    add     x0, x0, :lo12:__ttbr1_l0
    adrp    x1, __ttbr1_l1
    add     x1, x1, :lo12:__ttbr1_l1
    orr     x1, x1, #0x3
    str     x1, [x0]

    dsb     ishst
    ret

// =====================================================================
// .data.boot — bootstrap stack and page-table storage. Placed in the
// boot PT_LOAD segment by the direct-kernel linker script so QEMU
// loads zero-initialised bytes at their fixed LMAs.
// =====================================================================
    .section .data.boot,"aw",%progbits

    .balign 16
    .global __boot_stack_bottom
__boot_stack_bottom:
    .space 0x6000                   // 24 KiB stack (matches boot.protocol.STACK_SIZE)
    .global __boot_stack_top
__boot_stack_top:

    .balign 4096
    .global __boot_pagetables_start
__boot_pagetables_start:
    .global __ttbr0_l0
__ttbr0_l0:
    .space 4096
    .global __ttbr0_l1
__ttbr0_l1:
    .space 4096
    .global __ttbr0_l2_dev
__ttbr0_l2_dev:
    .space 4096
    .global __ttbr1_l0
__ttbr1_l0:
    .space 4096
    .global __ttbr1_l1
__ttbr1_l1:
    .space 4096
    .global __ttbr1_l2
__ttbr1_l2:
    .space 4096
    .global __boot_pagetables_end
__boot_pagetables_end:
