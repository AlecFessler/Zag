//! ARM Generic Interrupt Controller (GIC) driver — GICv2/v3 dual-mode.
//!
//! The GIC is the ARM equivalent of x86's APIC (Local APIC + IO APIC).
//! It handles interrupt routing, prioritization, and inter-processor interrupts.
//!
//! This driver supports both GICv2 (MMIO CPU interface) and GICv3 (system
//! register CPU interface). The version is detected at runtime by reading
//! GICD_PIDR2.ArchRev and exposed via the `gicv3` flag.
//!
//! GIC architecture references:
//! - ARM IHI 0069H: GICv3/v4 Architecture Specification
//! - ARM IHI 0048B: GICv2 Architecture Specification
//!
//!   Distributor (GICD_*): Global, one per system.
//!     - Manages SPI (Shared Peripheral Interrupt) enable/disable/routing.
//!     - Base address discovered from ACPI MADT GIC Distributor structure.
//!     - IHI 0069H, Section 8.9: GICD register summary.
//!     - IHI 0048B, Section 4.3: GICD register summary.
//!
//!   Redistributor (GICR_*, GICv3 only): One per core.
//!     - Manages SGI/PPI enable/priority for its core.
//!     - Discovered from ACPI MADT GIC Redistributor structure.
//!     - IHI 0069H, Section 9.5: GICR register summary.
//!
//!   CPU Interface:
//!     - GICv3: ICC_*_EL1 system registers (IHI 0069H, Section 12.11).
//!     - GICv2: GICC_* MMIO registers (IHI 0048B, Section 4.4).
//!     - Per-core, handles interrupt acknowledgement and EOI.
//!
//! Interrupt ID ranges (IHI 0069H, Section 2.2 / IHI 0048B, Section 2.2):
//!   0-15:    SGI (Software Generated Interrupts) — used for IPIs.
//!   16-31:   PPI (Private Peripheral Interrupts) — per-core (e.g., timer).
//!   32-1019: SPI (Shared Peripheral Interrupts) — device IRQs.
//!
//! Dispatch interface mapping:
//!   coreCount()                → count of cores discovered from MADT
//!   coreID()                   → read MPIDR_EL1 Aff0 field
//!   sendIpiToCore(id, vector)  → ICC_SGI1R_EL1 (v3) / GICD_SGIR (v2)
//!   maskIrq(irq)              → GICD_ICENABLER / GICR_ICENABLER (v3)
//!   unmaskIrq(irq)            → GICD_ISENABLER / GICR_ISENABLER (v3)
//!   endOfInterrupt(intid)     → ICC_EOIR1_EL1 (v3) / GICC_EOIR (v2)
//!   acknowledgeInterrupt()    → ICC_IAR1_EL1 (v3) / GICC_IAR (v2)
//!
//! References:
//! - ARM IHI 0069H: GICv3/v4 Architecture Specification
//! - ARM IHI 0048B: GICv2 Architecture Specification
//! - ARM ARM DDI 0487: D13.2.83 (MPIDR_EL1)

const std = @import("std");
const zag = @import("zag");

// ── GICD register offsets (IHI 0069H, Section 8.9 / IHI 0048B, Section 4.3) ──

/// Distributor register offsets relative to GICD base address.
/// IHI 0069H, Section 8.9, Table 8-1 "GICD register summary".
/// IHI 0048B, Section 4.3.1, Table 4-1 "Distributor register summary".
const GicdReg = enum(u32) {
    /// Distributor Control Register.
    /// IHI 0069H, Section 8.9.4 / IHI 0048B, Section 4.3.2.
    ctlr = 0x0000,
    /// Interrupt Controller Type Register.
    /// IHI 0069H, Section 8.9.5 / IHI 0048B, Section 4.3.3.
    typer = 0x0004,
    /// Distributor Implementer Identification Register.
    /// IHI 0069H, Section 8.9.6 / IHI 0048B, Section 4.3.4.
    iidr = 0x0008,
    /// Interrupt Group Registers (base).
    /// IHI 0069H, Section 8.9.10 / IHI 0048B, Section 4.3.10.
    /// GICD_IGROUPR<n> at offset 0x0080 + 4*n, one bit per INTID.
    /// Bit = 0 → Group 0, bit = 1 → Group 1 (non-secure).
    /// On both GICv2 and GICv3 the first register (IGROUPR0, INTIDs 0-31)
    /// is banked per-CPU, so each core writes its own copy.
    igroupr0 = 0x0080,
    /// Interrupt Set-Enable Registers (base).
    /// IHI 0069H, Section 8.9.7 / IHI 0048B, Section 4.3.5.
    /// GICD_ISENABLER<n> at offset 0x0100 + 4*n, each bit enables one INTID.
    isenabler0 = 0x0100,
    /// Interrupt Clear-Enable Registers (base).
    /// IHI 0069H, Section 8.9.8 / IHI 0048B, Section 4.3.6.
    /// GICD_ICENABLER<n> at offset 0x0180 + 4*n, each bit disables one INTID.
    icenabler0 = 0x0180,
    /// Interrupt Priority Registers (base).
    /// IHI 0069H, Section 8.9.11 / IHI 0048B, Section 4.3.11.
    /// GICD_IPRIORITYR<n> at offset 0x0400 + 4*n, 8 bits per INTID.
    ipriorityr0 = 0x0400,
    /// Interrupt Processor Targets Registers (base, GICv2 only).
    /// IHI 0048B, Section 4.3.12: GICD_ITARGETSR<n> at offset 0x0800 + 4*n,
    /// 8 bits per INTID, each byte is a CPU target bitmask.
    itargetsr0 = 0x0800,
    /// Interrupt Configuration Registers (base).
    /// IHI 0069H, Section 8.9.12 / IHI 0048B, Section 4.3.13.
    /// GICD_ICFGR<n> at offset 0x0C00 + 4*n, 2 bits per INTID.
    icfgr0 = 0x0C00,
    /// Software Generated Interrupt Register (GICv2 only).
    /// IHI 0048B, Section 4.3.15: bits [3:0] = INTID, [23:16] = target CPU list.
    sgir = 0x0F00,
    /// Peripheral ID2 Register — GICv2 variant at offset 0x0FE8.
    /// IHI 0048B, Section 4.3.17. ArchRev in bits [7:4]: 2=GICv2.
    pidr2 = 0x0FE8,
    /// Peripheral ID2 Register — GICv3/v4 variant at offset 0xFFE8.
    /// IHI 0069H, Section 12.8 (GICD_IDREGS). ArchRev in bits [7:4]:
    /// 3=GICv3, 4=GICv4.
    pidr2_v3 = 0xFFE8,
    /// Interrupt Routing Registers (base, GICv3 only).
    /// IHI 0069H, Section 8.9.13.
    /// GICD_IROUTER<n> at offset 0x6100 + 8*n, 64 bits per SPI (INTID 32+).
    irouter0 = 0x6100,
};

// ── GICC register offsets (IHI 0048B, Section 4.4) ─────────────

/// GICv2 CPU Interface register offsets relative to GICC base address.
/// IHI 0048B, Section 4.4, Table 4-2 "CPU interface register summary".
const GiccReg = enum(u32) {
    /// CPU Interface Control Register. IHI 0048B, Section 4.4.1.
    ctlr = 0x0000,
    /// Interrupt Priority Mask Register. IHI 0048B, Section 4.4.2.
    /// Interrupts with priority >= PMR value are masked.
    pmr = 0x0004,
    /// Binary Point Register. IHI 0048B, Section 4.4.3.
    bpr = 0x0008,
    /// Interrupt Acknowledge Register. IHI 0048B, Section 4.4.4.
    /// Acknowledges the highest priority pending Group 0 interrupt.
    iar = 0x000C,
    /// End of Interrupt Register. IHI 0048B, Section 4.4.5.
    /// Signals completion of the Group 0 interrupt.
    eoir = 0x0010,
    /// Aliased Interrupt Acknowledge Register. IHI 0048B, Section 4.4.11.
    /// Acknowledges the highest priority pending Group 1 interrupt. When
    /// GICC_IAR is read and the pending interrupt is Group 1, it returns
    /// the spurious INTID 1022 instead — GICC_AIAR is the correct ack
    /// path for Group 1 interrupts.
    aiar = 0x0020,
    /// Aliased End of Interrupt Register. IHI 0048B, Section 4.4.12.
    /// Signals completion of the Group 1 interrupt previously returned
    /// by GICC_AIAR.
    aeoir = 0x0024,
};

// ── GICR register offsets (IHI 0069H, Section 9.5) ─────────────

/// Redistributor register offsets relative to each GICR frame base.
/// Each redistributor has two 64KB frames: RD_base and SGI_base.
/// IHI 0069H, Section 9.5, Table 9-1 "GICR register summary".
const GicrReg = enum(u32) {
    /// Redistributor Control Register. IHI 0069H, Section 9.5.1.
    ctlr = 0x0000,
    /// Redistributor Type Register. IHI 0069H, Section 9.5.3.
    typer = 0x0008,
    /// Redistributor Wake Register. IHI 0069H, Section 9.5.5.
    waker = 0x0014,
};

/// SGI_base frame offsets (at RD_base + 0x10000).
/// IHI 0069H, Section 9.5, Table 9-2 "GICR_SGI_base register summary".
const GicrSgiReg = enum(u32) {
    /// SGI/PPI Interrupt Group Register. IHI 0069H, Section 9.5.2.
    /// Bit n = 0 → INTID n is Group 0 (secure);
    /// Bit n = 1 → INTID n is Group 1 Non-secure.
    igroupr0 = 0x0080,
    /// SGI/PPI Set-Enable Register. IHI 0069H, Section 9.5.6.
    isenabler0 = 0x0100,
    /// SGI/PPI Clear-Enable Register. IHI 0069H, Section 9.5.7.
    icenabler0 = 0x0180,
    /// SGI/PPI Priority Registers (base). IHI 0069H, Section 9.5.8.
    ipriorityr0 = 0x0400,
};

// ── GICD_CTLR bit definitions ──────────────────────────────────

/// Enable Affinity Routing (ARE_NS) for non-secure state (GICv3 only).
/// When set, SPIs use GICD_IROUTER for affinity-based routing.
/// IHI 0069H, Section 8.9.4, bit 4.
const gicd_ctlr_are_ns: u32 = 1 << 4;

/// Enable Group 1 non-secure interrupts at the Distributor.
/// IHI 0069H, Section 8.9.4, bit 1 / IHI 0048B, Section 4.3.2, bit 1.
const gicd_ctlr_enable_grp1_ns: u32 = 1 << 1;

/// Enable Group 0 interrupts at the Distributor.
/// IHI 0069H, Section 8.9.4, bit 0 / IHI 0048B, Section 4.3.2, bit 0.
const gicd_ctlr_enable_grp0: u32 = 1 << 0;

// ── GICR_WAKER bit definitions (IHI 0069H, Section 9.5.5) ──────

/// ProcessorSleep bit. Software sets this to 0 to wake the redistributor.
/// IHI 0069H, Section 9.5.5, bit 1.
const gicr_waker_processor_sleep: u32 = 1 << 1;

/// ChildrenAsleep bit. Hardware sets this to 0 when redistributor is awake.
/// IHI 0069H, Section 9.5.5, bit 2.
const gicr_waker_children_asleep: u32 = 1 << 2;

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of redistributors (one per core).
const max_redist: usize = 256;

/// Spurious interrupt ID returned by IAR when no pending interrupt.
/// IHI 0069H, Section 12.11.1 / IHI 0048B, Section 4.4.4.
pub const spurious_intid: u32 = 1023;

// ── State ───────────────────────────────────────────────────────

/// GICv3 detected flag. When false, the driver uses GICv2 MMIO paths.
/// Set during initDistributor() by reading GICD_PIDR2.ArchRev.
pub var gicv3: bool = false;

/// GICD base virtual address. Set by acpi.zig via setDistributorBase().
var gicd_base: u64 = 0;

/// GICC base virtual address (GICv2 only). Set via setGiccBase().
/// IHI 0048B, Section 4.4: CPU Interface register map.
var gicc_base: u64 = 0;

/// GICR base virtual addresses, one per core. Populated by acpi.zig via addRedistributor().
var gicr_bases: [max_redist]u64 = [_]u64{0} ** max_redist;

/// Number of redistributors populated in `gicr_bases`. Separate from
/// `core_count` (which tracks enabled CPU cores from MADT GICC entries)
/// so that setCoreCount + addRedistributor can be called in any order
/// without the two counters clobbering each other.
var redist_count: u64 = 0;

/// Number of cores discovered from MADT. Starts at 0; set via setCoreCount().
/// Defaults to 1 after init() if no cores were explicitly added (BSP-only fallback).
var core_count: u64 = 0;

/// Number of SPI lines supported by this GICD, derived from GICD_TYPER.
var max_spi_intid: u32 = 0;

// ── MMIO helpers ────────────────────────────────────────────────

fn gicdRead(reg: GicdReg) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(reg));
    return ptr.*;
}

fn gicdWrite(reg: GicdReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(reg));
    ptr.* = val;
}

fn gicdReadOffset(base_reg: GicdReg, byte_offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(base_reg) + byte_offset);
    return ptr.*;
}

fn gicdWriteOffset(base_reg: GicdReg, byte_offset: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(base_reg) + byte_offset);
    ptr.* = val;
}

fn giccRead(reg: GiccReg) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicc_base + @intFromEnum(reg));
    return ptr.*;
}

fn giccWrite(reg: GiccReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicc_base + @intFromEnum(reg));
    ptr.* = val;
}

fn gicrRead(core_idx: usize, reg: GicrReg) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicr_bases[core_idx] + @intFromEnum(reg));
    return ptr.*;
}

fn gicrWrite(core_idx: usize, reg: GicrReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicr_bases[core_idx] + @intFromEnum(reg));
    ptr.* = val;
}

fn gicrSgiRead(core_idx: usize, reg: GicrSgiReg) u32 {
    // SGI_base frame is at RD_base + 0x10000.
    // IHI 0069H, Section 9.1.
    const ptr: *const volatile u32 = @ptrFromInt(gicr_bases[core_idx] + 0x10000 + @intFromEnum(reg));
    return ptr.*;
}

fn gicrSgiWrite(core_idx: usize, reg: GicrSgiReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicr_bases[core_idx] + 0x10000 + @intFromEnum(reg));
    ptr.* = val;
}

// ── ICC system register accessors (IHI 0069H, Section 12.11) ───

/// Read ICC_SRE_EL1 — System Register Enable.
/// IHI 0069H, Section 12.11.3.
fn readIccSre() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], S3_0_C12_C12_5"
        : [val] "=r" (val),
    );
    return val;
}

/// Write ICC_SRE_EL1 — System Register Enable.
/// IHI 0069H, Section 12.11.3: bit 0 = SRE (enable system register interface).
fn writeIccSre(val: u64) void {
    asm volatile ("msr S3_0_C12_C12_5, %[val]"
        :
        : [val] "r" (val),
    );
    asm volatile ("isb");
}

/// Write ICC_PMR_EL1 — Priority Mask Register.
/// IHI 0069H, Section 12.11.2: interrupts with priority >= PMR value are masked.
/// Writing 0xFF allows all priority levels.
fn writeIccPmr(val: u64) void {
    asm volatile ("msr S3_0_C4_C6_0, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write ICC_IGRPEN1_EL1 — Interrupt Group 1 Enable.
/// IHI 0069H, Section 12.11.6: bit 0 = Enable Group 1 interrupts.
fn writeIccIgrpen1(val: u64) void {
    asm volatile ("msr S3_0_C12_C12_7, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Read ICC_IAR1_EL1 — Interrupt Acknowledge Register (Group 1).
/// IHI 0069H, Section 12.11.1: returns the INTID of the highest priority
/// pending Group 1 interrupt, or 1023 (spurious) if none pending.
fn readIccIar1() u32 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], S3_0_C12_C12_0"
        : [val] "=r" (val),
    );
    return @intCast(val & 0xFFFFFF);
}

/// Write ICC_EOIR1_EL1 — End of Interrupt Register (Group 1).
/// IHI 0069H, Section 12.11.1: write the INTID to signal completion.
fn writeIccEoir1(intid: u32) void {
    const val: u64 = intid;
    asm volatile ("msr S3_0_C12_C12_1, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write ICC_SGI1R_EL1 — SGI Generation Register (Group 1).
/// IHI 0069H, Section 12.11.8.
fn writeIccSgi1r(val: u64) void {
    asm volatile ("msr S3_0_C12_C11_5, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write ICC_BPR1_EL1 — Binary Point Register (Group 1).
/// IHI 0069H, Section 12.11.4: controls priority grouping for preemption.
/// A value of 0 means all 8 priority bits are used for preemption grouping.
fn writeIccBpr1(val: u64) void {
    asm volatile ("msr S3_0_C12_C12_3, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Read MPIDR_EL1 — Multiprocessor Affinity Register.
/// ARM ARM D13.2.83: Aff0 [7:0] = core, Aff1 [15:8] = cluster,
/// Aff2 [23:16], Aff3 [39:32].
fn readMpidr() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], mpidr_el1"
        : [val] "=r" (val),
    );
    return val;
}

// ── ACPI discovery interface ────────────────────────────────────

/// Set the GICD base virtual address. Called by acpi.zig when parsing the
/// MADT GIC Distributor structure (ACPI 6.5, Table 5-47, type 0x0C).
pub fn setDistributorBase(addr: u64) void {
    gicd_base = addr;
}

/// Set the GICC base virtual address for GICv2 CPU interface.
/// Called by acpi.zig when parsing the MADT GICC structure, or by DTB
/// parsing for the GICv2 CPU interface memory region.
///
/// IHI 0048B, Section 4.4: CPU Interface register map.
pub fn setGiccBase(addr: u64) void {
    gicc_base = addr;
}

/// Register a redistributor base virtual address. Called by acpi.zig for each
/// core discovered from MADT GIC Redistributor structures (ACPI 6.5, type 0x0E)
/// or by iterating the redistributor discovery region.
///
/// Must be called in core index order (core 0, core 1, ...).
pub fn addRedistributor(addr: u64) void {
    const idx: usize = @intCast(redist_count);
    if (idx >= max_redist) return;
    gicr_bases[idx] = addr;
    redist_count += 1;
}

/// Set the core count directly (e.g., from counting MADT GICC structures).
pub fn setCoreCount(count: u64) void {
    core_count = count;
}

// ── Initialization ──────────────────────────────────────────────

/// Initialize the GIC distributor. Called once on the BSP during boot.
///
/// Detects the GIC version by reading GICD_PIDR2.ArchRev (bits [7:4]).
/// IHI 0069H, Section 8.9.15 / IHI 0048B, Section 4.3.17:
///   ArchRev 2 = GICv2, ArchRev 3 = GICv3/v4.
///
/// For GICv3: enables affinity routing (ARE) and Group 1 non-secure
/// interrupts. SPIs are routed via GICD_IROUTER.
///
/// For GICv2: enables Group 1 non-secure interrupts without ARE. SPIs
/// are routed via GICD_ITARGETSR (8-bit CPU target mask per INTID).
///
/// All SPIs are disabled initially — they are unmasked individually when
/// device drivers request them.
///
/// IHI 0069H, Section 8.9.4: GICD_CTLR register (GICv3).
/// IHI 0048B, Section 4.3.2: GICD_CTLR register (GICv2).
/// IHI 0069H, Section 8.9.5 / IHI 0048B, Section 4.3.3:
///   GICD_TYPER — ITLinesNumber field [4:0] gives (max SPI INTID / 32) - 1.
pub fn initDistributor() void {
    if (gicd_base == 0) return;

    // Detect GIC version from GICD_PIDR2.ArchRev [7:4].
    //
    // GICv2 exposes PIDR2 at offset 0x0FE8 (IHI 0048B, Section 4.3.17)
    // and its GICD MMIO window is only 4 KiB wide — offsets >= 0x1000
    // are unassigned memory. Reading GICv3's PIDR2_v3 slot (0xFFE8)
    // on a GICv2 implementation raises a synchronous external abort
    // (QEMU TCG `-M virt` with the default GICv2) or hangs.
    //
    // Probe GICv2 first. If ArchRev[7:4] == 2 we know we are on
    // GICv2 and MUST NOT touch offset 0xFFE8. Only fall through to
    // the GICv3 probe when the v2 slot shows something else (typical
    // on a genuine GICv3: 0xFE8 reads back zero because it's reserved).
    const pidr2_v2_val = gicdRead(.pidr2);
    const arch_rev_v2 = (pidr2_v2_val >> 4) & 0xF;
    var arch_rev: u32 = arch_rev_v2;
    if (arch_rev_v2 != 2) {
        const pidr2_v3_val = gicdRead(.pidr2_v3);
        const arch_rev_v3 = (pidr2_v3_val >> 4) & 0xF;
        if (arch_rev_v3 >= 3) arch_rev = arch_rev_v3;
    }
    gicv3 = (arch_rev >= 3);

    // Disable the distributor while reconfiguring.
    gicdWrite(.ctlr, 0);

    // Read the number of supported SPI interrupt lines.
    // IHI 0069H, Section 8.9.5 / IHI 0048B, Section 4.3.3:
    // GICD_TYPER.ITLinesNumber [4:0].
    const typer = gicdRead(.typer);
    const it_lines = typer & 0x1F;
    max_spi_intid = (it_lines + 1) * 32;

    // Disable all SPIs (INTID 32+). SGIs/PPIs (0-31) are per-core.
    // IHI 0069H, Section 8.9.8 / IHI 0048B, Section 4.3.6: GICD_ICENABLER<n>.
    var n: u32 = 1;
    while (n < (max_spi_intid / 32)) {
        gicdWriteOffset(.icenabler0, n * 4, 0xFFFFFFFF);
        n += 1;
    }

    // Set all SPI priorities to the lowest (0xFF).
    // IHI 0069H, Section 8.9.11 / IHI 0048B, Section 4.3.11:
    // GICD_IPRIORITYR<n>, 8 bits per INTID.
    n = 8; // Start at INTID 32 (byte offset 32 = register index 8).
    while (n < (max_spi_intid / 4)) {
        gicdWriteOffset(.ipriorityr0, n * 4, 0xFFFFFFFF);
        n += 1;
    }

    // Set all SPIs to edge-triggered by default.
    // IHI 0069H, Section 8.9.12 / IHI 0048B, Section 4.3.13:
    // GICD_ICFGR<n>, 2 bits per INTID. Bit [1] = 1 for edge-triggered.
    n = 2; // Start at INTID 32 (register index 2).
    while (n < (max_spi_intid / 16)) {
        gicdWriteOffset(.icfgr0, n * 4, 0xAAAAAAAA);
        n += 1;
    }

    if (gicv3) {
        // GICv3: Route all SPIs to core 0 via GICD_IROUTER.
        // IHI 0069H, Section 8.9.13: GICD_IROUTER<n>, 64-bit, one per SPI.
        // IROUTER starts at INTID 32, so register 0 = INTID 32.
        var intid: u32 = 32;
        while (intid < max_spi_intid) {
            const offset = (intid - 32) * 8;
            const ptr: *volatile u64 = @ptrFromInt(gicd_base + @intFromEnum(GicdReg.irouter0) + offset);
            ptr.* = 0; // Aff0=0 targets core 0.
            intid += 1;
        }

        // Enable distributor with affinity routing and Group 1.
        // IHI 0069H, Section 8.9.4: ARE_NS (bit 4), EnableGrp1NS (bit 1).
        gicdWrite(.ctlr, gicd_ctlr_are_ns | gicd_ctlr_enable_grp1_ns | gicd_ctlr_enable_grp0);
    } else {
        // GICv2: Route all SPIs to CPU 0 via GICD_ITARGETSR.
        // IHI 0048B, Section 4.3.12: GICD_ITARGETSR<n>, 8 bits per INTID,
        // each byte is a CPU target bitmask (bit 0 = CPU 0, etc.).
        // INTIDs 0-31 are read-only (banked per-CPU), start at INTID 32.
        n = 8; // Byte offset 32 = register index 8 (4 INTIDs per register).
        while (n < (max_spi_intid / 4)) {
            gicdWriteOffset(.itargetsr0, n * 4, 0x01010101); // All 4 INTIDs → CPU 0.
            n += 1;
        }

        // Enable distributor for Group 1 NS interrupts.
        //
        // IHI 0048B, Section 4.3.2, Table 4-21 (GICD_CTLR, Non-secure view):
        // when accessed from Non-secure state — which is the only view
        // exposed by KVM's in-kernel GICv2 emulation and by TCG GICv2
        // without the security extensions — bit 0 alone is the Group 1
        // enable, and the Secure-view bits 0 (EnableGrp0) / 1
        // (EnableGrp1NS) are not visible. We write both bit 0 (NS view
        // enable) and bit 1 (Secure-view EnableGrp1NS) so the same
        // value works regardless of which view the implementation
        // exposes. Linux's gic.c uses GICD_ENABLE = 0x1.
        gicdWrite(.ctlr, gicd_ctlr_enable_grp1_ns | gicd_ctlr_enable_grp0);
    }
}

/// Wake a redistributor for the given core index (GICv3 only).
///
/// Clears GICR_WAKER.ProcessorSleep and polls until GICR_WAKER.ChildrenAsleep
/// is cleared by hardware, indicating the redistributor is fully awake.
///
/// IHI 0069H, Section 9.5.5: GICR_WAKER.
fn wakeRedistributor(core_idx: usize) void {
    if (gicr_bases[core_idx] == 0) return;

    // Clear ProcessorSleep (bit 1).
    var waker = gicrRead(core_idx, .waker);
    waker &= ~gicr_waker_processor_sleep;
    gicrWrite(core_idx, .waker, waker);

    // Wait for ChildrenAsleep (bit 2) to clear.
    while (gicrRead(core_idx, .waker) & gicr_waker_children_asleep != 0) {
        std.atomic.spinLoopHint();
    }
}

/// Initialize the redistributor for the given core index.
///
/// On GICv3: wakes the redistributor, enables all SGIs (INTID 0-15), and
/// sets default priority for SGIs/PPIs via GICR registers.
///
/// On GICv2: no redistributor exists. SGI/PPI configuration is done via
/// GICD registers (GICD_ISENABLER0, GICD_IPRIORITYR0-7), which are banked
/// per-CPU on GICv2.
///
/// IHI 0069H, Section 9.5.
/// IHI 0048B, Section 4.3.5: GICD_ISENABLER0 is banked per-CPU for INTIDs 0-31.
/// IHI 0048B, Section 4.3.11: GICD_IPRIORITYR0-7 is banked per-CPU for INTIDs 0-31.
pub fn initRedistributor(core_idx: usize) void {
    if (gicd_base == 0) return;
    if (gicv3) {
        wakeRedistributor(core_idx);

        // Assign all SGIs/PPIs to Group 1 Non-secure. After reset
        // GICR_IGROUPR0 is UNKNOWN and some implementations leave every
        // INTID in Group 0. We only enable ICC_IGRPEN1_EL1 on the CPU
        // interface, so any PPI left in Group 0 (notably CNTV PPI 27)
        // would be silently dropped. IHI 0069H, Section 9.5.2.
        gicrSgiWrite(core_idx, .igroupr0, 0xFFFFFFFF);

        // Enable SGIs (INTID 0-15) and the generic timer PPIs
        // (27 = CNTV, 29 = CNTHP, 30 = CNTP) via GICR_ISENABLER0.
        // IHI 0069H, Section 9.5.6: GICR_ISENABLER0 — bit n enables INTID n.
        // The scheduler uses the virtual timer (CNTV, PPI 27) because it
        // is always accessible from EL1 without EL2 having to enable
        // CNTHCTL_EL2.EL1PCEN. The physical timer PPI (30) is kept
        // enabled as well for generic timer support.
        gicrSgiWrite(core_idx, .isenabler0, 0x0000FFFF | (1 << 27) | (1 << 29) | (1 << 30));

        // Set all SGI/PPI priorities to 0x80. On GICv3 ICC_PMR_EL1 is
        // 0xFF and interrupts with priority >= PMR are masked (IHI 0069H,
        // Section 12.11.2), so writing 0xFF into IPRIORITYR would silently
        // suppress every PPI — including the preemption timer. 0x80 is
        // well below the mask.
        // IHI 0069H, Section 9.5.8: GICR_IPRIORITYR<n>. Write via raw
        // pointer arithmetic rather than @enumFromInt on an offset that
        // is not one of GicrSgiReg's named members (the enum is
        // exhaustive, so a synthetic value is undefined behaviour).
        var n: u32 = 0;
        while (n < 8) {
            const addr = gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.ipriorityr0) + n * 4;
            const ptr: *volatile u32 = @ptrFromInt(addr);
            ptr.* = 0x80808080;
            n += 1;
        }
    } else {
        // GICv2: SGI/PPI registers are in GICD, banked per-CPU.
        //
        // Assign all SGIs/PPIs to Group 1 Non-secure via the banked
        // GICD_IGROUPR0. After reset this register is UNKNOWN (KVM
        // GICv2 emulation + AAVMF leaves every INTID in Group 0). The
        // CPU interface is enabled for Group 1, so any PPI left in
        // Group 0 — notably the CNTV preemption timer PPI 27 — would
        // be silently dropped. IHI 0048B, Section 4.3.10.
        gicdWriteOffset(.igroupr0, 0, 0xFFFFFFFF);

        // Enable SGIs (INTID 0-15) and timer PPIs (27, 29, 30) via the
        // banked GICD_ISENABLER0.
        // IHI 0048B, Section 4.3.5.
        gicdWriteOffset(.isenabler0, 0, 0x0000FFFF | (1 << 27) | (1 << 29) | (1 << 30));

        // Set all SGI/PPI priorities to 0x80 (see GICv3 note above).
        // IHI 0048B, Section 4.3.11: GICD_IPRIORITYR0-7 (banked per-CPU).
        var n: u32 = 0;
        while (n < 8) {
            gicdWriteOffset(.ipriorityr0, n * 4, 0x80808080);
            n += 1;
        }
    }
}

/// Initialize the CPU interface on the current core.
///
/// On GICv3: enables ICC system register interface, sets priority mask to
/// allow all interrupts, and enables Group 1 interrupt signaling.
///
/// On GICv2: configures the GICC MMIO registers for priority mask, binary
/// point, and enables the CPU interface.
///
/// GICv3 references:
///   IHI 0069H, Section 12.11.3: ICC_SRE_EL1 — SRE bit enables sys reg interface.
///   IHI 0069H, Section 12.11.2: ICC_PMR_EL1 — 0xFF allows all priorities.
///   IHI 0069H, Section 12.11.4: ICC_BPR1_EL1 — binary point for preemption.
///   IHI 0069H, Section 12.11.6: ICC_IGRPEN1_EL1 — bit 0 enables Group 1.
///
/// GICv2 references:
///   IHI 0048B, Section 4.4.2: GICC_PMR — 0xFF allows all priorities.
///   IHI 0048B, Section 4.4.3: GICC_BPR — binary point for preemption.
///   IHI 0048B, Section 4.4.1: GICC_CTLR — bit 0 enables the CPU interface.
pub fn initCpuInterface() void {
    if (gicv3) {
        // Enable system register interface.
        var sre = readIccSre();
        sre |= 0x1; // SRE bit.
        writeIccSre(sre);

        // Set priority mask to allow all interrupt priorities.
        writeIccPmr(0xFF);

        // Set binary point to 0 (no sub-priority grouping).
        writeIccBpr1(0);

        // Enable Group 1 interrupts.
        writeIccIgrpen1(0x1);
    } else {
        if (gicc_base == 0) return;

        // Set priority mask to allow all interrupt priorities.
        // IHI 0048B, Section 4.4.2: GICC_PMR.
        giccWrite(.pmr, 0xFF);

        // Set binary point to 0 (no sub-priority grouping).
        // IHI 0048B, Section 4.4.3: GICC_BPR.
        giccWrite(.bpr, 0);

        // Enable the CPU interface for Group 1 non-secure.
        //
        // IHI 0048B, Section 4.4.1, Table 4-46 (GICC_CTLR, Non-secure view):
        // when accessed from Non-secure state, the bit positions are
        // remapped — bit 0 becomes EnableGrp1 (the "enable" bit for the
        // OS), bit 5 = FIQBypDisGrp1, bit 6 = IRQBypDisGrp1, bit 9 =
        // EOImodeNS. The Secure-view layout (bit 0 = EnableGrp0,
        // bit 1 = EnableGrp1NS) is NOT visible from a Non-secure OS.
        //
        // KVM's in-kernel GICv2 emulation (and TCG GICv2 without the
        // security extensions) only exposes the Non-secure view, so a
        // write of 0x2 lands on a reserved bit and leaves the CPU
        // interface disabled — no Group 1 interrupt is ever forwarded
        // to the core. Writing 0x1 is what Linux's gic.c does
        // (GICC_ENABLE = 0x1). We additionally set bit 1 so that on a
        // GICv2 implementation that does expose the Secure view this
        // also enables Group 1 NS, matching the previous behaviour.
        giccWrite(.ctlr, 0x3);
    }
}

/// Full GIC initialization for the BSP (boot core).
///
/// Initializes the distributor, the BSP's redistributor (index 0), and the
/// BSP's CPU interface. Secondary cores call initSecondaryCoreGic() instead.
pub fn init() void {
    initDistributor();
    initRedistributor(0);
    initCpuInterface();
}

/// Initialize GIC for a secondary core.
///
/// Wakes the core's redistributor and enables the CPU interface.
/// The distributor is already initialized by the BSP.
pub fn initSecondaryCoreGic(core_idx: usize) void {
    initRedistributor(core_idx);
    initCpuInterface();
}

// ── Public API ──────────────────────────────────────────────────

/// Return the number of cores discovered from ACPI MADT.
pub fn coreCount() u64 {
    return if (core_count == 0) 1 else core_count;
}

/// Return the current core's logical ID derived from MPIDR_EL1.
///
/// Uses Aff0 [7:0] for flat topology (single cluster). For multi-cluster
/// systems, this should be extended to incorporate Aff1/Aff2/Aff3.
///
/// ARM ARM D13.2.83: MPIDR_EL1.
pub fn coreID() u64 {
    const mpidr = readMpidr();
    return mpidr & 0xFF; // Aff0.
}

/// Acknowledge the highest priority pending interrupt.
///
/// On GICv3: reads ICC_IAR1_EL1 (IHI 0069H, Section 12.11.1).
/// On GICv2: reads GICC_AIAR. The driver assigns every INTID to Group 1
/// non-secure, so GICC_IAR (Group 0 ack) would return the spurious
/// INTID 1022 whenever a Group 1 interrupt is pending.
/// IHI 0048B, Section 4.4.11 (aliased IAR).
///
/// Returns the INTID, or `spurious_intid` (1023) if no interrupt is pending.
pub fn acknowledgeInterrupt() u32 {
    if (gicv3) return readIccIar1();
    return giccRead(.aiar) & 0x3FF; // IHI 0048B: INTID in bits [9:0].
}

/// Signal end of interrupt processing for the given INTID.
///
/// On GICv3: writes ICC_EOIR1_EL1 (IHI 0069H, Section 12.11.1).
/// On GICv2: writes GICC_AEOIR (IHI 0048B, Section 4.4.12), the Group 1
/// pair to GICC_AIAR.
///
/// Must be called after the interrupt handler completes. For level-triggered
/// SPIs, the peripheral must deassert the interrupt line before EOI to
/// avoid re-triggering.
pub fn endOfInterrupt(intid: u32) void {
    if (gicv3) {
        writeIccEoir1(intid);
    } else {
        giccWrite(.aeoir, intid);
    }
}

/// Send an IPI (SGI) to the specified core.
///
/// On GICv3: writes ICC_SGI1R_EL1 with the target affinity and SGI INTID.
/// ICC_SGI1R_EL1 layout (IHI 0069H, Section 12.11.8):
///   [3:0]   — TargetList: bitmask of target cores within the target affinity.
///   [23:16] — Aff1: target cluster.
///   [27:24] — INTID: SGI interrupt number (0-15).
///   [39:32] — Aff2.
///   [40]    — IRM: 0 = use target list, 1 = all except self.
///   [55:48] — Aff3.
///
/// On GICv2: writes GICD_SGIR.
/// IHI 0048B, Section 4.3.15: GICD_SGIR layout:
///   [3:0]   — INTID: SGI interrupt number (0-15).
///   [23:16] — CPUTargetList: bitmask of target CPUs.
///   [25:24] — TargetListFilter: 0 = use CPUTargetList.
///
/// For a flat topology (single cluster, Aff1=Aff2=Aff3=0), only the
/// TargetList and INTID fields matter.
pub fn sendIpiToCore(core_id: u64, vector: u8) void {
    // SGI INTID must be 0-15.
    const sgi_id: u64 = vector & 0xF;

    if (gicv3) {
        // For flat topology, core_id maps to Aff0 directly.
        // TargetList is a bitmask within the lowest affinity level.
        const target_list: u64 = @as(u64, 1) << @intCast(core_id & 0xF);

        // Build ICC_SGI1R_EL1 value.
        // IHI 0069H, Section 12.11.8.
        const sgi_val: u64 = target_list | // [15:0] TargetList
            (sgi_id << 24); // [27:24] INTID

        writeIccSgi1r(sgi_val);
    } else {
        // GICv2: write GICD_SGIR.
        // IHI 0048B, Section 4.3.15: [3:0] = INTID, [23:16] = CPUTargetList,
        // [25:24] = TargetListFilter (0 = use CPUTargetList).
        const target_mask: u32 = @as(u32, 1) << @intCast(core_id & 0x7);
        const sgir_val: u32 = @as(u32, @intCast(sgi_id)) | (target_mask << 16);
        gicdWrite(.sgir, sgir_val);
    }
}

/// Mask (disable) an interrupt.
///
/// For SPIs (INTID >= 32), writes the corresponding GICD_ICENABLER register.
/// For SGIs/PPIs (INTID 0-31):
///   GICv3 — writes GICR_ICENABLER0 on the current core.
///   GICv2 — writes GICD_ICENABLER0 (banked per-CPU).
///
/// IHI 0069H, Section 8.9.8: GICD_ICENABLER<n>.
/// IHI 0069H, Section 9.5.7: GICR_ICENABLER0.
/// IHI 0048B, Section 4.3.6: GICD_ICENABLER0 (banked per-CPU for INTID 0-31).
pub fn maskIrq(intid: u32) void {
    const bit: u32 = @as(u32, 1) << @intCast(intid & 0x1F);
    const reg_offset: u32 = (intid / 32) * 4;

    if (intid < 32) {
        if (gicv3) {
            // SGI/PPI — use redistributor for current core.
            const core_idx: usize = @intCast(coreID());
            const ptr: *volatile u32 = @ptrFromInt(
                gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.icenabler0),
            );
            ptr.* = bit;
        } else {
            // GICv2: GICD_ICENABLER0 is banked per-CPU for INTID 0-31.
            gicdWriteOffset(.icenabler0, 0, bit);
        }
        return;
    }

    // SPI — use distributor (same for v2 and v3).
    gicdWriteOffset(.icenabler0, reg_offset, bit);
}

/// Unmask (enable) an interrupt.
///
/// For SPIs (INTID >= 32), writes the corresponding GICD_ISENABLER register.
/// For SGIs/PPIs (INTID 0-31):
///   GICv3 — writes GICR_ISENABLER0 on the current core.
///   GICv2 — writes GICD_ISENABLER0 (banked per-CPU).
///
/// IHI 0069H, Section 8.9.7: GICD_ISENABLER<n>.
/// IHI 0069H, Section 9.5.6: GICR_ISENABLER0.
/// IHI 0048B, Section 4.3.5: GICD_ISENABLER0 (banked per-CPU for INTID 0-31).
pub fn unmaskIrq(intid: u32) void {
    const bit: u32 = @as(u32, 1) << @intCast(intid & 0x1F);
    const reg_offset: u32 = (intid / 32) * 4;

    if (intid < 32) {
        if (gicv3) {
            // SGI/PPI — use redistributor for current core.
            const core_idx: usize = @intCast(coreID());
            const ptr: *volatile u32 = @ptrFromInt(
                gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.isenabler0),
            );
            ptr.* = bit;
        } else {
            // GICv2: GICD_ISENABLER0 is banked per-CPU for INTID 0-31.
            gicdWriteOffset(.isenabler0, 0, bit);
        }
        return;
    }

    // SPI — use distributor (same for v2 and v3).
    gicdWriteOffset(.isenabler0, reg_offset, bit);
}

/// Route an SPI to a specific core.
///
/// On GICv3: writes GICD_IROUTER<n> with MPIDR-format affinity.
/// IHI 0069H, Section 8.9.13: GICD_IROUTER<n>.
///
/// On GICv2: writes GICD_ITARGETSR for the INTID's byte with a CPU bitmask.
/// IHI 0048B, Section 4.3.12: GICD_ITARGETSR<n>, 8 bits per INTID.
pub fn routeSpiToCore(intid: u32, target_core: u64) void {
    if (intid < 32) return; // SGIs/PPIs are not routed via GICD_IROUTER/ITARGETSR.
    if (gicd_base == 0) return;

    if (gicv3) {
        const offset = (intid - 32) * 8;
        const ptr: *volatile u64 = @ptrFromInt(gicd_base + @intFromEnum(GicdReg.irouter0) + offset);
        // For flat topology, target_core is the Aff0 value directly.
        ptr.* = target_core & 0xFF;
    } else {
        // GICv2: each INTID has an 8-bit target field in GICD_ITARGETSR.
        // Read-modify-write the containing 32-bit register.
        // IHI 0048B, Section 4.3.12.
        const reg_offset: u32 = (intid / 4) * 4;
        const byte_pos: u5 = @intCast((intid % 4) * 8);
        const addr = gicd_base + @intFromEnum(GicdReg.itargetsr0) + reg_offset;
        const ptr: *volatile u32 = @ptrFromInt(addr);
        const cpu_mask: u32 = @as(u32, 1) << @intCast(target_core & 0x7);
        var val = ptr.*;
        val &= ~(@as(u32, 0xFF) << byte_pos);
        val |= cpu_mask << byte_pos;
        ptr.* = val;
    }
}

/// Set the priority of an interrupt.
///
/// Lower values = higher priority. Priority is 8 bits per INTID.
///
/// For SPIs: uses GICD_IPRIORITYR (same for v2/v3).
/// For SGIs/PPIs:
///   GICv3 — uses GICR_IPRIORITYR (IHI 0069H, Section 9.5.8).
///   GICv2 — uses GICD_IPRIORITYR (banked per-CPU, IHI 0048B, Section 4.3.11).
pub fn setPriority(intid: u32, priority: u8) void {
    const byte_offset = intid;
    const reg_offset = (byte_offset / 4) * 4;
    const byte_pos: u5 = @intCast((byte_offset % 4) * 8);

    if (intid < 32) {
        if (gicv3) {
            // SGI/PPI — use redistributor.
            const core_idx: usize = @intCast(coreID());
            const addr = gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.ipriorityr0) + reg_offset;
            const ptr: *volatile u32 = @ptrFromInt(addr);
            var val = ptr.*;
            val &= ~(@as(u32, 0xFF) << byte_pos);
            val |= @as(u32, priority) << byte_pos;
            ptr.* = val;
        } else {
            // GICv2: GICD_IPRIORITYR0-7 is banked per-CPU for INTID 0-31.
            const addr = gicd_base + @intFromEnum(GicdReg.ipriorityr0) + reg_offset;
            const ptr: *volatile u32 = @ptrFromInt(addr);
            var val = ptr.*;
            val &= ~(@as(u32, 0xFF) << byte_pos);
            val |= @as(u32, priority) << byte_pos;
            ptr.* = val;
        }
        return;
    }

    // SPI — use distributor (same for v2 and v3).
    const addr = gicd_base + @intFromEnum(GicdReg.ipriorityr0) + reg_offset;
    const ptr: *volatile u32 = @ptrFromInt(addr);
    var val = ptr.*;
    val &= ~(@as(u32, 0xFF) << byte_pos);
    val |= @as(u32, priority) << byte_pos;
    ptr.* = val;
}

/// Configure an SPI as edge-triggered or level-sensitive.
///
/// IHI 0069H, Section 8.9.12 / IHI 0048B, Section 4.3.13:
/// GICD_ICFGR<n>, 2 bits per INTID.
/// Bit [1] of the 2-bit field: 0 = level-sensitive, 1 = edge-triggered.
pub fn configureTrigger(intid: u32, edge_triggered: bool) void {
    if (intid < 32) return; // SGI/PPI config is fixed or via GICR.
    if (gicd_base == 0) return;

    const reg_index = intid / 16;
    const bit_offset: u5 = @intCast((intid % 16) * 2 + 1);
    const reg_addr = gicd_base + @intFromEnum(GicdReg.icfgr0) + reg_index * 4;

    const ptr: *volatile u32 = @ptrFromInt(reg_addr);
    var val = ptr.*;
    if (edge_triggered) {
        val |= @as(u32, 1) << bit_offset;
    } else {
        val &= ~(@as(u32, 1) << bit_offset);
    }
    ptr.* = val;
}
