//! aarch64 EL2 → EL1 drop for the UEFI bootloader.
//!
//! When QEMU is invoked with `-M virt,virtualization=on -bios AAVMF`,
//! AAVMF boots and runs its entire DXE/BDS phase at EL2. Our Zag UEFI
//! bootloader is therefore called at EL2 and inherits an EL2 MMU
//! (SCTLR_EL2.M=1, TTBR0_EL2 identity-mapping firmware + the loaded
//! bootloader image). If we simply `br kEntry` into the kernel from
//! EL2, two things break:
//!
//!   (a) kEntry lives at a TTBR1 high VA; TTBR1_EL1 is not consulted
//!       by the EL2 translation regime, so the fetch faults.
//!   (b) The Zag kernel unconditionally assumes it runs at EL1 and
//!       operates TTBR0/TTBR1_EL1, SCTLR_EL1, MAIR_EL1, CPACR_EL1,
//!       VBAR_EL1 — none of which govern an EL2 MMU.
//!
//! So right before `switchStackAndCall` (which is where the bootloader
//! hands off control), we:
//!
//!   1. Read TTBR0_EL2 / TCR_EL2 / MAIR_EL2 / SCTLR_EL2 — the MMU state
//!      the firmware set up and that our currently-executing bootloader
//!      code depends on.
//!   2. Mirror that state into the corresponding EL1 sysregs. TTBR0_EL1
//!      is a direct copy (identity-mapped PA==VA in the low half). TCR
//!      needs field rearrangement because TCR_EL2 is a single-regime
//!      layout and TCR_EL1 is two-regime; we preserve T0SZ/IRGN0/ORGN0/
//!      SH0/TG0, translate PS→IPS, and OR in T1SZ/TG1/... that the
//!      bootloader's TTBR1 kernel_code mappings need.
//!   3. Install a minimal EL2 hyp stub vector table at VBAR_EL2 so an
//!      EL1 `hvc` trap has somewhere to land. The kernel replaces this
//!      with its own `__hyp_vectors` (kernel/arch/aarch64/boot/start.S)
//!      during `vmInit` / world-switch setup.
//!   4. Give the dispatcher a dedicated SP_EL2 and a clean TPIDR_EL2.
//!   5. ERET into EL1 (SPSR_EL2 = 0x3C5 = EL1h + DAIF masked, ELR_EL2 =
//!      label after the ERET sequence), setting SP_EL1 first so EL1
//!      exceptions have a stack.
//!
//! After the ERET the bootloader resumes at EL1 with the same logical
//! state — same MMU contents (identity low half + kernel high half),
//! same calling conventions — and `switchStackAndCall(kEntry, ...)`
//! proceeds as in the normal UEFI-at-EL1 path.
//!
//! The bootloader records `arrived_at_el2 = 1` in BootInfo so the
//! kernel knows to set `vm.hyp_stub_installed = true` after it runs,
//! unlocking `vmSupported()` and the s4_2_* VM syscall tests.
//!
//! References:
//!   ARM ARM K.a
//!     D13.2.28  HCR_EL2
//!     D13.2.29  HSTR_EL2
//!     D13.2.51  MAIR_EL1 / D13.2.52 MAIR_EL2
//!     D13.2.117 SCTLR_EL1 / D13.2.118 SCTLR_EL2
//!     D13.2.131 TCR_EL1 / D13.2.132 TCR_EL2
//!     D13.2.144 TTBR0_EL1 / D13.2.145 TTBR0_EL2
//!   Linux arm64 `arch/arm64/kernel/head.S` (`el2_setup` path) for the
//!   same idea, though Linux additionally disables+re-enables the MMU
//!   because its boot protocol requires MMU-off at entry. We keep the
//!   MMU on across the drop so the bootloader can continue executing
//!   without setting up a fresh identity map of its own code.

const std = @import("std");

/// Small EL2 stack for the minimal hyp vector table. Must be 16-byte
/// aligned per AAPCS64. Lives in the bootloader's .bss so it is valid
/// after exitBootServices (loader_data stays mapped until we actually
/// overwrite it).
var hyp_stack: [0x2000]u8 align(16) = undefined;

// ===========================================================================
// Minimal EL2 hyp stub vector table (bootloader-local).
//
// Only the "sync from lower EL, AArch64" vector at offset 0x400 is used;
// every other vector halts in a tight loop. Nothing in the bootloader or
// the very early kernel path intentionally issues exceptions to EL2 —
// this table exists so that stray traps (e.g. HVC from buggy EL1 code
// before the kernel installs its own __hyp_vectors) are observable as a
// hang rather than an undefined jump.
//
// For the "sync lower A64" vector we ERET unconditionally: the HVC trap
// already advanced ELR_EL2 past the HVC, so a bare ERET resumes EL1 at
// the next instruction. The kernel's real hyp stub (start.S) replaces
// this once vmInit runs, so this table only needs to survive the brief
// window between the bootloader's ERET-to-EL1 and the kernel's own
// VBAR_EL2 install.
//
// `.naked` + `export` gets us a proper symbol we can take `&` of; the
// 2-KiB alignment required by VBAR_EL2 is enforced by placing the
// function in its own section with an explicit alignment below.
// ===========================================================================

export fn bootloader_hyp_vectors() align(2048) callconv(.naked) void {
    asm volatile (
    // +0x000 — sync EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x080 — irq EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x100 — fiq EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x180 — serror EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x200 — sync EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x280 — irq EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x300 — fiq EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x380 — serror EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x400 — sync lower EL A64: bare eret (handles HVC-to-noop).
        \\        eret
        \\        .balign 0x80
        // +0x480 — irq lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x500 — fiq lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x580 — serror lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x600..+0x780 — lower AArch32 (unused on a 64-bit-only kernel)
        \\        b       .
        \\        .balign 0x80
        \\        b       .
        \\        .balign 0x80
        \\        b       .
        \\        .balign 0x80
        \\        b       .
    );
}

/// Read CurrentEL.EL (bits [3:2]). 0=EL0, 1=EL1, 2=EL2, 3=EL3.
pub fn currentEl() u8 {
    var v: u64 = 0;
    asm volatile ("mrs %[v], CurrentEL"
        : [v] "=r" (v),
    );
    return @intCast((v >> 2) & 0x3);
}

/// Drop from EL2 to EL1 in place, preserving the active MMU state.
///
/// Must be called:
///   - with the MMU enabled at EL2 (firmware configuration),
///   - AFTER `setKernelAddrSpace()` has loaded a kernel table into
///     TTBR1_EL1 (TTBR0_EL1 is populated here from TTBR0_EL2), and
///   - BEFORE `switchStackAndCall(kEntry, ...)`.
///
/// On return, we are at EL1h, with MMU still on, same identity mapping
/// in TTBR0_EL1 and the kernel-side mappings in TTBR1_EL1. `sp` has
/// been preserved across the drop via SP_EL1. All GP regs other than
/// x0..x9 clobbered by the drop sequence itself are preserved by
/// saving them to the stack around the call because we compile with
/// `callconv(.c)`.
pub fn dropToEl1() void {
    // Pre-resolve the bootloader hyp vector table address and stack
    // top in pure Zig so the asm below doesn't have to relocate them.
    const hyp_vbar: u64 = @intFromPtr(&bootloader_hyp_vectors);
    const hyp_sp_top: u64 = @intFromPtr(&hyp_stack) + hyp_stack.len;

    asm volatile (
    // -------------------------------------------------------------
    // 1. Mirror EL2 MMU state into EL1 sysregs.
    //
    //    TTBR0_EL1 <- TTBR0_EL2         (identity map covering us)
    //    MAIR_EL1  <- MAIR_EL2          (same attribute indices)
    //    TCR_EL1   <- TCR_EL2 low half  + T1SZ/TG1/SH1/IRGN1/ORGN1
    //                                    + IPS in bits [34:32]
    //    SCTLR_EL1 <- RES1 | (SCTLR_EL2 & {M,C,I,SA})
    //    VBAR_EL1  <- VBAR_EL2          (stray EL1 traps land
    //                                    somewhere observable until
    //                                    early_fault installs ours)
    // -------------------------------------------------------------
        \\        mrs     x9,  ttbr0_el2
        \\        msr     ttbr0_el1, x9
        \\
        \\        mrs     x9,  mair_el2
        \\        msr     mair_el1, x9
        \\
        // Build TCR_EL1 from TCR_EL2.
        //
        // TCR_EL2 layout (single regime, bits we care about):
        //   [5:0]    T0SZ
        //   [9:8]    IRGN0
        //   [11:10]  ORGN0
        //   [13:12]  SH0
        //   [15:14]  TG0
        //   [18:16]  PS  (physical address size)
        //   [20]     TBI
        //
        // TCR_EL1 layout (two regimes):
        //   [5:0]    T0SZ
        //   [9:8]    IRGN0
        //   [11:10]  ORGN0
        //   [13:12]  SH0
        //   [15:14]  TG0
        //   [21:16]  T1SZ
        //   [23]     A1
        //   [25:24]  IRGN1
        //   [27:26]  ORGN1
        //   [29:28]  SH1
        //   [31:30]  TG1  (0b10 = 4KB)
        //   [34:32]  IPS
        //   [37:36]  AS, [38] TBI0, [39] TBI1 (leave zero)
        //
        // Low 16 bits transfer directly. Extract PS from [18:16] of
        // TCR_EL2 and place it at [34:32] of TCR_EL1. OR in the
        // standard kernel TTBR1 configuration (same values the Zag
        // kernel would write via enableKernelTranslation()):
        //   T1SZ  = 16
        //   IRGN1 = 0b01 (WB-WA)
        //   ORGN1 = 0b01 (WB-WA)
        //   SH1   = 0b11 (Inner Shareable)
        //   TG1   = 0b10 (4KB)
        \\        mrs     x9,  tcr_el2
        \\        and     x10, x9, #0xFFFF            // T0SZ/IRGN0/ORGN0/SH0/TG0
        \\        and     x11, x9, #(0x7 << 16)       // PS in [18:16]
        \\        lsl     x11, x11, #16               // move to [34:32]
        \\        orr     x10, x10, x11
        \\        mov     x11, #(16 << 16)            // T1SZ
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x1 << 24)           // IRGN1[0]
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x1 << 26)           // ORGN1[0]
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x3 << 28)           // SH1
        \\        orr     x10, x10, x11
        \\        mov     x11, #(0x2 << 30)           // TG1 = 4KB
        \\        orr     x10, x10, x11
        \\        msr     tcr_el1, x10
        \\
        // SCTLR_EL1: start from the RES1 reset pattern (bits 29,28,23,
        // 22,20,11 set) and OR in the {M,C,I,SA} bits from SCTLR_EL2
        // so the EL1 regime inherits whatever enable flags firmware
        // had turned on. Linux uses the same trick (init_el2_state ->
        // __cpu_setup). Bit positions:
        //   [0]  M   MMU enable
        //   [2]  C   Data cache enable
        //   [3]  SA  SP alignment check enable
        //   [12] I   Instruction cache enable
        //
        // RES1 mask = (1<<29)|(1<<28)|(1<<23)|(1<<22)|(1<<20)|(1<<11)
        //           = 0x30D0_0800
        \\        mrs     x9,  sctlr_el2
        \\        mov     x10, #0x0800                // bit 11
        \\        movk    x10, #0x30D0, lsl #16       // bits 29,28,23,22,20
        \\        mov     x11, #((1<<0)|(1<<2)|(1<<3)|(1<<12))
        \\        and     x9,  x9, x11
        \\        orr     x9,  x9, x10
        \\        msr     sctlr_el1, x9
        \\
        \\        mrs     x9,  vbar_el2
        \\        msr     vbar_el1, x9
        \\
        \\        isb
        \\
        // -------------------------------------------------------------
        // 2. HCR_EL2.RW = 1 so EL1 executes A64. Leave the rest as
        //    reset defaults — the kernel reconfigures HCR_EL2 when it
        //    starts a guest.
        // -------------------------------------------------------------
        \\        mov     x9, #1
        \\        lsl     x9, x9, #31
        \\        msr     hcr_el2, x9
        \\
        // CPTR_EL2: don't trap FP/SIMD to EL2. Matches Linux.
        \\        mov     x9, #0x33FF
        \\        msr     cptr_el2, x9
        \\
        // CPACR_EL1.FPEN = 0b11 (don't trap EL0/EL1 FP/SIMD to EL1).
        // Without this the first FP/SIMD use in the kernel (Zig's
        // struct copies etc.) raises EC=0x07 at EL1.
        \\        mov     x9, #(0x3 << 20)
        \\        msr     cpacr_el1, x9
        \\
        // -------------------------------------------------------------
        // 3. Install the bootloader's minimal hyp vector table and
        //    dedicated SP_EL2; clear TPIDR_EL2 (world-switch "no
        //    active vCPU" marker).
        // -------------------------------------------------------------
        \\        msr     vbar_el2, %[hyp_vbar]
        \\        msr     tpidr_el2, xzr
        \\        isb
        \\
        // -------------------------------------------------------------
        // 4. ERET to EL1h with DAIF masked. Before the eret, write
        //    SP_EL1 = our current (EL2) sp so that after the exception
        //    return, the EL1 CPU (using SP_EL1 because PSTATE.SP=1 via
        //    EL1h) resumes on the exact same C stack frame. Then repoint
        //    the active SP at the dedicated hyp stack — that becomes
        //    SP_EL2 and will be used by any future exception taken to
        //    EL2 (e.g. the kernel's world switch once it reinstalls
        //    its own __hyp_vectors).
        // -------------------------------------------------------------
        \\        mov     x9,  sp
        \\        msr     sp_el1, x9
        \\        msr     sp_el0, xzr
        \\
        \\        mov     sp, %[hyp_sp_top]           // SP_EL2 = hyp_stack_top
        \\
        \\        adr     x9, 1f
        \\        msr     elr_el2, x9
        \\        mov     x9, #0x3C5                  // EL1h + DAIF masked
        \\        msr     spsr_el2, x9
        \\        isb
        \\        eret
        \\1:
        :
        : [hyp_vbar] "r" (hyp_vbar),
          [hyp_sp_top] "r" (hyp_sp_top),
        : .{ .memory = true, .x9 = true, .x10 = true, .x11 = true }
    );
}
