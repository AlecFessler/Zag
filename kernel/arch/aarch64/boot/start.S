// aarch64 direct-kernel boot entry.
//
// This file is ONLY linked into the kernel when `-Ddirect_kernel=true`
// is passed to `zig build`. In that mode the kernel ELF is loaded by
// QEMU's `-kernel` machinery (`qemu-system-aarch64 -M virt \
// -machine virtualization=on -kernel kernel.elf`) and enters at
// `_start` with:
//
//     x0 = physical address of the device tree blob (DTB)
//     PC = ELF entry point (`_start`)
//     EL = EL2 when `virtualization=on`, EL1 otherwise
//     MMU off, caches off, SP undefined
//
// The default UEFI build path (`kernel.entry = "kEntry"`) is untouched
// by this file and keeps working — the AAVMF bootloader still calls
// straight into `kEntry` at EL1 with x0=BootInfo*.
//
// Why a separate entry: the EL2 sysregs the aarch64 KVM object layer
// needs (HCR_EL2, VTTBR_EL2, VTCR_EL2, VBAR_EL2, ICH_*, TLBI IPAS2E1IS)
// are completely inaccessible from the EL1-only UEFI boot path. The
// Debian/Ubuntu AAVMF_CODE.fd on this host can't be booted with
// `virtualization=on` (it crashes inside its own firmware), so the
// only way to reach EL2 in TCG is to bypass AAVMF via `-kernel`.
//
// Boot phases, developed incrementally:
//
//   Phase 1 — minimal. Print "E2\n" from EL2 and halt. Proves the
//             split-layout ELF loads and runs. (commit 9345a85)
//
//   Phase 2 — this file. Configure HCR_EL2/CPTR_EL2, set up MAIR_EL1 /
//             TCR_EL1 / TTBR0_EL1 with an identity 16 MiB map starting
//             at 0x40000000, enable SCTLR_EL1.M|C|I, ERET to EL1t with
//             MMU on. Land at `phase2_el1_landing` (low-VA identity
//             mapped), print "2M E1\n", halt. Proves the full EL2 →
//             EL1 drop works under translation.
//
//   Phase 3 — parse the DTB in x19 into a synthesized BootInfo (memory
//             map from /memory nodes, root_service from @embedFile),
//             install TTBR1 high-VA mapping so kernel VAs work, jump
//             to `kEntry` with the BootInfo pointer.
//
//   Phase 4 — install an EL2 hyp-stub vector (VBAR_EL2), leave space
//             for the vmResume trampoline. kEntry runs normally at
//             EL1; VM entry/exit uses HVC.
//
// Markers emitted on the PL011 UART (0x09000000) so that any crash mid-
// sequence can be localised just from the serial tail:
//
//     "2"   — EL2 entry reached, stack up
//     "M"   — MMU enabled at EL1 sysreg level, about to ERET
//     "E1"  — EL1 landing pad executed (post-ERET, translation live)
//
// Each marker is emitted exactly once, in order, so the final serial
// output for a healthy phase 2 boot is:
//
//     2M E1
//
// Register conventions inside this file:
//     x19 — saved DTB phys addr (x0 at entry). Preserved across calls.
//     x9..x18 — scratch. Do not rely on their value across any `bl`.
//
// References:
//   ARM ARM D13.2.25   CurrentEL
//   ARM ARM D13.2.46   HCR_EL2
//   ARM ARM D13.2.30   CPTR_EL2
//   ARM ARM D13.2.97   MAIR_EL1
//   ARM ARM D13.2.131  TCR_EL1
//   ARM ARM D13.2.132  TTBR0_EL1 / TTBR1_EL1
//   ARM ARM D13.2.118  SCTLR_EL1
//   ARM ARM D1.11      Exception entry/return (ERET semantics)
//   ARM ARM D5.3.3     VMSAv8-64 stage-1 block/table descriptors
//   QEMU docs/system/arm/virt.rst  — direct-kernel boot ABI

// =====================================================================
// .text.boot — entry code. Must stay in the low-PA boot segment so we
// can execute it with the MMU off. Keep all subroutines called before
// phase2_el1_landing in this section; once we're past ERET, we can
// start using high-VA code.
// =====================================================================

    .section .text.boot,"ax",%progbits
    .global _start
_start:
    // Detect how we were entered.
    //
    // UEFI path: AAVMF drops to EL1 long before us, and the Zag
    // bootloader calls the ELF entry symbol with x0 = BootInfo*.
    // Detect this by reading CurrentEL and tail-calling `kEntry` so
    // that this file can be linked into UEFI builds too without
    // breaking them. (In practice `-Ddirect_kernel=true` is the only
    // build that includes this file, so the EL1 branch is dormant.)
    //
    // Direct-kernel path: QEMU enters us at EL2 with x0 = DTB phys.
    // Fall through to the real init sequence below.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #1
    b.eq    el1_uefi_entry
    // fall through to EL2 direct-kernel entry

    // Save DTB phys addr. It's the one thing from QEMU we must keep
    // across every helper call until we hand it to kEntry in Phase 3.
    mov     x19, x0

    // Bring up the bootstrap stack. __boot_stack_top lives in
    // .data.boot, identity-loaded by QEMU at a known low PA, so an
    // adrp+:lo12: reference works with the MMU still off.
    adrp    x9, __boot_stack_top
    add     x9, x9, :lo12:__boot_stack_top
    mov     sp, x9

    // Marker '2' — reached EL2 entry, stack valid, about to touch
    // sysregs. If serial stops here the problem is in sysreg access
    // or the HCR_EL2 / CPTR_EL2 sequence.
    mov     w0, #'2'
    bl      uart_putc

    // HCR_EL2.RW = 1: EL1 executes in AArch64. This bit is IMP-DEF at
    // reset on some parts, so set it explicitly before doing anything
    // that depends on EL1 state. All other HCR_EL2 bits are zero for
    // now — VM=0 (stage-2 off), TGE=0 (no host OS semantics), no
    // traps. The KVM vmResume path will flip the relevant bits per
    // guest entry, not here.
    mov     x9, #1
    lsl     x9, x9, #31
    msr     hcr_el2, x9
    isb

    // CPTR_EL2: allow FP/SIMD access from lower ELs without trapping
    // to EL2. The 0x33FF value matches the architecturally required
    // bits plus TFP=0 / TCPAC=0 — the same pattern Linux arm64 uses
    // when coming up at EL2 before dropping to EL1.
    mov     x9, #0x33FF
    msr     cptr_el2, x9
    isb

    // MAIR_EL1:
    //   index 0 = 0xFF — Normal, Inner WB RA+WA, Outer WB RA+WA (for RAM)
    //   index 1 = 0x00 — Device-nGnRnE (for PL011 UART MMIO)
    //   all other indices are 0 (device-nGnRnE) which is fine unused.
    ldr     x9, =0x00000000000000FF
    msr     mair_el1, x9

    // TCR_EL1:
    //   T0SZ=16, TG0=4K, SH0=IS, IRGN0=WB, ORGN0=WB  (TTBR0 walk config)
    //   T1SZ=16, TG1=4K, SH1=IS, IRGN1=WB, ORGN1=WB  (TTBR1 walk config)
    //   IPS=40-bit
    // TTBR1 is set to the same L0 as TTBR0 below; with no entries it
    // will fault any high-VA access, which is what we want for Phase 2.
    ldr     x9, =0x00000002B5103510
    msr     tcr_el1, x9

    // Zero the three page-table pages reserved in .data.boot, then
    // write the descriptors for a 16 MiB identity map at 0x40000000.
    // That range covers the entire direct-kernel ELF image (boot
    // stub + kernel text/rodata/data, both at ≤ a few MB from that
    // base) with plenty of headroom.
    bl      zero_boot_pagetables
    bl      build_ttbr0_identity

    // Point both TTBRs at the boot L0 table. TTBR1 walks will miss
    // because no high-VA entries are populated — that's OK for phase
    // 2, we won't execute at a high VA yet. Phase 3 extends the L0
    // to cover the kernel's 0xFFFF000000000000 range.
    adrp    x9, __ttbr0_l0
    add     x9, x9, :lo12:__ttbr0_l0
    msr     ttbr0_el1, x9
    msr     ttbr1_el1, x9

    // Ensure page-table stores are visible to the page-table walker
    // before enabling translation. `dsb ishst` gates stores; `isb`
    // prevents the subsequent SCTLR_EL1 write from reordering past.
    dsb     ishst
    isb

    // Enable EL1 MMU + data/instr caches. Preserve the RES1 bits
    // already set in SCTLR_EL1 by the CPU reset state.
    mrs     x9, sctlr_el1
    orr     x9, x9, #(1 << 0)   // M — MMU enable at EL1
    orr     x9, x9, #(1 << 2)   // C — data cache enable at EL1
    orr     x9, x9, #(1 << 12)  // I — instruction cache enable at EL1
    msr     sctlr_el1, x9
    dsb     ish
    isb

    // Marker 'M' — SCTLR_EL1 programmed; about to ERET down into EL1
    // with the identity map active. Note this still prints with EL2
    // SCTLR_EL2.M=0, so the MMU being "on" here refers only to the
    // EL1 state we're setting up for after ERET.
    mov     w0, #'M'
    bl      uart_putc

    // Prepare ERET: land at phase2_el1_landing (low-VA, TTBR0 walks).
    // SPSR_EL2 = 0x3C5 ⇒ M[3:0]=0101 (EL1h, stack=SP_EL1), DAIF all
    // masked. x0 carries the DTB pointer for the landing pad's use
    // (Phase 3 will consume it).
    adrp    x9, phase2_el1_landing
    add     x9, x9, :lo12:phase2_el1_landing
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
// Phase-2 EL1 landing.
//
// Still in the low-PA identity region (TTBR0 walk active, TTBR1
// empty). Job: prove translation works end-to-end by emitting a
// marker and halting. Phase 3 will replace this stub with a real
// hand-off into the high-VA kEntry.
// -----------------------------------------------------------------
phase2_el1_landing:
    // SP was set on the EL2 side but hardware swaps to SP_EL1 on
    // exception entry. Reload it so the helper calls have a stack.
    adrp    x9, __boot_stack_top
    add     x9, x9, :lo12:__boot_stack_top
    mov     sp, x9

    mov     w0, #' '
    bl      uart_putc
    mov     w0, #'E'
    bl      uart_putc
    mov     w0, #'1'
    bl      uart_putc
    mov     w0, #'\n'
    bl      uart_putc
1:  wfe
    b       1b

// -----------------------------------------------------------------
// Helpers. All run with the MMU off (EL2 side) and therefore must be
// position-stable at their LMA — keep them in .text.boot.
// -----------------------------------------------------------------

// w0 = byte to send. Writes PL011 DR at 0x09000000. The QEMU PL011
// model accepts raw byte writes to DR without any FCR/LCR/CR setup
// at reset, so a single store suffices.
uart_putc:
    ldr     x1, =0x09000000
    strb    w0, [x1]
    ret

// Zero all four boot page tables (L0 + L1 + L2_ram + L2_dev = 16 KiB).
zero_boot_pagetables:
    adrp    x0, __ttbr0_l0
    add     x0, x0, :lo12:__ttbr0_l0
    mov     x1, #(4 * 4096)
1:  str     xzr, [x0], #8
    subs    x1, x1, #8
    b.ne    1b
    ret

// Build the TTBR0 identity map. Two level-2 tables so that a single
// L1 covers both the device range (L1[0], contains PL011 at
// 0x09000000) and the kernel RAM range (L1[1], PA 0x40000000+):
//
//   L2_ram[0..7] — 2 MiB Normal-WB blocks, PA 0x40000000 .. 0x41000000
//   L2_dev[72]   — 2 MiB Device-nGnRnE block, PA 0x09000000 .. 0x09200000
//                  (index = 0x09000000 >> 21 = 72 in the L1[0] 1 GiB slot)
//   L1[0] → L2_dev   (VA 0x00000000..0x40000000)
//   L1[1] → L2_ram   (VA 0x40000000..0x80000000)
//   L0[0] → L1
//
// Block descriptor encoding (ARM ARM D5.3.3):
//   [0]    = 1                valid
//   [1]    = 0                block (at level 2)
//   [4:2]  = AttrIndx         0 = Normal WB, 1 = Device-nGnRnE
//   [7:6]  = 00               AP — RW at EL1, no EL0 access
//   [9:8]  = 11               SH — inner shareable
//   [10]   = 1                AF — access flag
//   [47:21]= PA>>21           2 MiB-aligned physical block address
//
//   → Normal WB block low bits = 0x701
//   → Device   block low bits = 0x705  (AttrIdx=1 means bit 2 = 1)
build_ttbr0_identity:
    // L2_ram: 8 block descriptors mapping 16 MiB at 0x40000000.
    adrp    x0, __ttbr0_l2_ram
    add     x0, x0, :lo12:__ttbr0_l2_ram
    ldr     x1, =0x0000000040000000
    mov     x2, #0x701
    mov     x3, #8
1:  orr     x4, x1, x2
    str     x4, [x0], #8
    add     x1, x1, #0x200000       // +2 MiB
    subs    x3, x3, #1
    b.ne    1b

    // L2_dev[72] = device block for 0x09000000 .. 0x09200000. This
    // covers the PL011 UART (0x09000000) and the RTC (0x09010000),
    // which is enough for Phase 2 debug output. Index 72 = 0x48.
    adrp    x0, __ttbr0_l2_dev
    add     x0, x0, :lo12:__ttbr0_l2_dev
    ldr     x1, =0x0000000009000000
    mov     x2, #0x705              // Device-nGnRnE block
    orr     x4, x1, x2
    str     x4, [x0, #(72 * 8)]

    // L1[0] → L2_dev (VA range [0, 1 GiB))
    adrp    x0, __ttbr0_l1
    add     x0, x0, :lo12:__ttbr0_l1
    adrp    x1, __ttbr0_l2_dev
    add     x1, x1, :lo12:__ttbr0_l2_dev
    orr     x1, x1, #0x3            // table descriptor: valid | table
    str     x1, [x0, #0]

    // L1[1] → L2_ram (VA range [1 GiB, 2 GiB))
    adrp    x1, __ttbr0_l2_ram
    add     x1, x1, :lo12:__ttbr0_l2_ram
    orr     x1, x1, #0x3
    str     x1, [x0, #8]

    // L0[0] → L1
    adrp    x0, __ttbr0_l0
    add     x0, x0, :lo12:__ttbr0_l0
    adrp    x1, __ttbr0_l1
    add     x1, x1, :lo12:__ttbr0_l1
    orr     x1, x1, #0x3
    str     x1, [x0]

    dsb     ishst                   // tables visible to the walker
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
    .space 4096
    .global __boot_stack_top
__boot_stack_top:

    .balign 4096
    .global __ttbr0_l0
__ttbr0_l0:
    .space 4096
    .global __ttbr0_l1
__ttbr0_l1:
    .space 4096
    .global __ttbr0_l2_ram
__ttbr0_l2_ram:
    .space 4096
    .global __ttbr0_l2_dev
__ttbr0_l2_dev:
    .space 4096
