// aarch64 direct-kernel boot entry.
//
// This file is ONLY linked into the kernel when `-Ddirect_kernel=true`
// is passed to `zig build`. In that mode the kernel ELF is loaded by
// QEMU's `-kernel` machinery (see `-M virt,virtualization=on -kernel
// kernel.elf`) and enters at `_start` with:
//
//     x0 = physical address of the device tree blob (DTB)
//     PC = ELF entry point (`_start`)
//     EL = EL2 when `virtualization=on`, EL1 otherwise
//     MMU off, caches off, SP undefined
//
// The default (UEFI / AAVMF) build path uses `ENTRY(kEntry)` and this
// file is not built — the bootloader runs under EL1 UEFI, parses the
// kernel ELF, applies KASLR, and jumps straight at `kEntry` with x0
// pointing at a populated BootInfo. That flow is unchanged.
//
// Why a separate entry at all: the UEFI AAVMF firmware on this host
// drops us to EL1 before our code runs and cannot be booted with
// `virtualization=on` (it faults inside the firmware). EL2 access is
// a hard prerequisite for the aarch64 KVM object layer (stage-2
// translation, HCR_EL2, VTTBR_EL2, ERET-into-guest, vGIC maintenance).
// `-kernel` + `virtualization=on` bypasses AAVMF entirely and lets us
// enter at EL2 directly. See commit 7f54009 (`el2_probe.S`) for the
// validation run.
//
// Phase 1 (this file): minimal stub. Prints a marker over the PL011
// UART at 0x09000000 and halts. Verifies only that
//   (a) QEMU `-kernel` can load the split-layout kernel ELF,
//   (b) the `_start` symbol lands at the expected LMA,
//   (c) we reach EL2 on `virtualization=on`.
//
// Phase 2+ will extend this into a real boot path: set up bootstrap
// page tables (TTBR0 identity + TTBR1 kernel VA), install an EL2 hyp
// stub vector, drop to EL1, parse the DTB in x0 to synthesize a
// `BootInfo`, and jump into `kEntry` with that pointer in x0.
//
// References:
//   - ARM ARM D13.2.25  CurrentEL
//   - ARM ARM D1.11     Exception entry/return (ERET semantics for drop-to-EL1)
//   - QEMU docs/system/arm/virt.rst  "Boot options" (direct-kernel boot)

    .section .text.boot,"ax",%progbits
    .global _start
_start:
    // UEFI path sanity: if we were entered at EL1 with a non-null x0,
    // we were called by the Zag UEFI bootloader with x0 = *BootInfo.
    // Tail-call kEntry in that case so the existing boot flow continues
    // to work even when this file is linked in.
    //
    // Under the intended direct-kernel boot we arrive at EL2 with x0 =
    // DTB physical address, which is fine for the fall-through path.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #1
    b.eq    el1_uefi_entry
    // fall through to EL2 direct-kernel entry

el2_direct_entry:
    // Phase 1 stub: emit "E2\n" on PL011 DR and halt.
    ldr     x9, =0x09000000
    mov     w10, #'E'
    strb    w10, [x9]
    mov     w10, #'2'
    strb    w10, [x9]
    mov     w10, #'\n'
    strb    w10, [x9]
1:  wfe
    b       1b

el1_uefi_entry:
    // Tail-call kEntry(*BootInfo). x0 already carries the BootInfo
    // pointer set up by the UEFI bootloader.
    //
    // We cannot reach kEntry via a direct B instruction because its
    // VMA (0xFFFF000000...) is far outside the ±128 MiB branch range.
    // Load the absolute VMA via a literal pool entry and branch. This
    // is safe only at EL1 with the kernel TTBR1 mapping already live,
    // which is exactly the state the bootloader hands us in.
    ldr     x9, =kEntry
    br      x9
