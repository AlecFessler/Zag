//! In-kernel vGICv3 (virtual Generic Interrupt Controller).
//!
//! ============================================================================
//! WHAT THIS FILE IMPLEMENTS
//! ============================================================================
//!
//! On x86 Zag has two files:
//!   kernel/arch/x64/kvm/lapic.zig   (in-kernel LAPIC emulation)
//!   kernel/arch/x64/kvm/ioapic.zig  (in-kernel IOAPIC emulation)
//!
//! The aarch64 analogue is a single GICv3 emulator covering:
//!
//!   1. The distributor (GICD) MMIO page — shared across the VM's vCPUs.
//!      Holds priority/enable/pending/active state for SPIs (32..1019).
//!      GICv3 §9.2 / §12.9 register map.
//!
//!   2. One redistributor (GICR) per vCPU — per-cpu MMIO page holding
//!      PPI + SGI state for that vCPU (0..31). Each redistributor is a
//!      pair of 64KB frames (RD_base + SGI_base). GICv3 §9.4 / §12.10.
//!
//!   3. The virtual CPU interface, programmed via system registers:
//!        ICH_HCR_EL2, ICH_VMCR_EL2, ICH_AP0R<n>_EL2, ICH_AP1R<n>_EL2,
//!        ICH_LR<n>_EL2, ICH_MISR_EL2, ICH_EISR_EL2, ICH_ELRSR_EL2.
//!      These are what actually deliver a virtual interrupt to the guest.
//!      GICv3 §11 / ARM ARM D13.8.
//!
//! On ARM the distributor and CPU interface are one logical interrupt
//! controller, so this file is sized like lapic.zig + ioapic.zig combined.
//!
//! ============================================================================
//! SPEC REFERENCES
//! ============================================================================
//!
//! Primary:
//!   - docs/aarch64/IHI0069_gicv3.pdf  -- GICv3/GICv4 Architecture Specification
//!       §2      Interrupt types and identifiers (SGI / PPI / SPI / LPI)
//!       §4.5    Interrupt handling state machine
//!       §4.7    Virtual interrupts
//!       §5      Virtualization extensions overview
//!       §8      Programmers' model for GICv3 (GICD/GICR register maps)
//!       §9.2    The Distributor register map
//!       §9.4    Redistributor register map
//!       §11.2   List registers
//!       §11.4   Maintenance interrupts
//!       §11.5   End of interrupt handling for virtual interrupts
//!       §12     Programmers' model for GICv3 system registers
//!   - docs/aarch64/102142_aarch64_virtualization.pdf §5 "Virtual interrupts"
//!   - docs/aarch64/DDI0487_arm_arm.pdf D13.8 "GIC control registers"
//!
//! Secondary (Linux reference implementation):
//!   - arch/arm64/kvm/vgic/vgic.c, vgic-v3.c, vgic-mmio-v3.c, vgic-init.c
//!     Cited inline below where Linux clarifies a corner the spec leaves
//!     under-specified (active-pending state transitions, LR allocation,
//!     EOImode quirks, maintenance IRQ underflow refill).

const std = @import("std");
const zag = @import("zag");

const vm_hw = zag.arch.aarch64.vm;

const SpinLock = zag.utils.sync.SpinLock;

/// Walk the kernel page tables to resolve a kernel VA (from any of the
/// kernel_code / kernel_heap / physmap partitions) into its physical
/// address. Used to hand per-vCPU shadow buffers to the EL2 hyp stubs,
/// which run with SCTLR_EL2.M=0 and therefore dereference their input
/// pointer as a raw PA. ARM ARM D5.2 table walk.
fn shadowKernelPA(vaddr: u64) u64 {
    const VAddr = zag.memory.address.VAddr;
    const paging = zag.arch.aarch64.paging;
    const memory_init = zag.memory.init;
    const base = vaddr & ~@as(u64, 0xFFF);
    const offset = vaddr & 0xFFF;
    const page_pa = paging.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(base),
    ) orelse @panic("shadowKernelPA: unmapped shadow VA");
    return page_pa.addr | offset;
}

// ===========================================================================
// Compile-time configuration
// ===========================================================================

/// Compile-time maximum SPI count. GICv3 supports up to 988 SPIs (INTID
/// 32..1019) but small guests rarely need more than 256. Linux KVM caps
/// this per-VM via KVM_DEV_ARM_VGIC_GRP_NR_IRQS; 256 SPIs covers anything
/// hyprvOS / routerOS guests need.
pub const MAX_SPIS: u16 = 256;

/// Total number of distributor INTIDs (32 SGI/PPI + MAX_SPIS).
/// Note: SGI/PPI state is per-vCPU and lives in the redistributor;
/// distributor SPI state starts at INTID 32. GICv3 §2.2.1.
pub const TOTAL_DIST_INTIDS: u16 = 32 + MAX_SPIS;

/// Number of list registers we expose. The GICv3 spec allows 1..16
/// (ICH_VTR_EL2.ListRegs+1; GICv3 §12.5.27). The Pi 5 (Cortex-A76)
/// implements 4. We size the shadow to the architectural maximum so
/// the same struct works on any host; `num_lrs` is set at init from
/// ICH_VTR_EL2 and is the only count actually used in the LR loops.
pub const MAX_LRS: u8 = 16;

/// Number of GICv3 SGIs (INTIDs 0..15). GICv3 §2.2.1.
pub const NUM_SGIS: u16 = 16;

/// Number of GICv3 PPIs (INTIDs 16..31). GICv3 §2.2.1.
pub const NUM_PPIS: u16 = 16;

/// Number of SGI+PPI INTIDs. These are the INTIDs whose state is owned
/// by the redistributor (per-vCPU) rather than the distributor (per-VM).
pub const NUM_SGI_PPI: u16 = NUM_SGIS + NUM_PPIS;

// ===========================================================================
// Guest-physical layout
// ===========================================================================

/// Base guest-physical addresses for the emulated GICD and GICR pages.
/// These are the ARM equivalent of x86's LAPIC_BASE / IOAPIC_BASE. The
/// guestMap overlap check (in kvm/vm.zig) must reject any region
/// overlapping either.
///
/// Default layout matches the QEMU virt machine + Linux KVM defaults
/// (also what hyprvOS advertises in its synthetic device tree):
///   GICD_BASE        0x08000000  size 0x10000   (single page-set, GICv3 §12.9)
///   GICR_BASE        0x080A0000  size 0x20000 * num_vcpus
///                                (RD_base 64K + SGI_base 64K per vCPU,
///                                 GICv3 §12.10)
///
/// GICv3 §12 gives the register map; the bases themselves are a
/// convention the hypervisor picks (they are advertised to the guest via
/// ACPI MADT or device tree).
pub const GICD_BASE: u64 = 0x08000000;
pub const GICD_SIZE: u64 = 0x10000;
pub const GICR_BASE: u64 = 0x080A0000;
pub const GICR_STRIDE: u64 = 0x20000;
pub const GICR_RD_FRAME_SIZE: u64 = 0x10000;
pub const GICR_SGI_FRAME_OFFSET: u64 = 0x10000;

// ===========================================================================
// GICD register offsets (GICv3 §12.9 Distributor register summary)
// ===========================================================================

const GICD_CTLR: u64 = 0x0000;
const GICD_TYPER: u64 = 0x0004;
const GICD_IIDR: u64 = 0x0008;
const GICD_TYPER2: u64 = 0x000C;
const GICD_STATUSR: u64 = 0x0010;
const GICD_SETSPI_NSR: u64 = 0x0040;
const GICD_CLRSPI_NSR: u64 = 0x0048;
const GICD_IGROUPR_BASE: u64 = 0x0080; // §12.9.10
const GICD_IGROUPR_END: u64 = 0x00FC;
const GICD_ISENABLER_BASE: u64 = 0x0100; // §12.9.7
const GICD_ISENABLER_END: u64 = 0x017C;
const GICD_ICENABLER_BASE: u64 = 0x0180; // §12.9.8
const GICD_ICENABLER_END: u64 = 0x01FC;
const GICD_ISPENDR_BASE: u64 = 0x0200; // §12.9.9
const GICD_ISPENDR_END: u64 = 0x027C;
const GICD_ICPENDR_BASE: u64 = 0x0280;
const GICD_ICPENDR_END: u64 = 0x02FC;
const GICD_ISACTIVER_BASE: u64 = 0x0300;
const GICD_ISACTIVER_END: u64 = 0x037C;
const GICD_ICACTIVER_BASE: u64 = 0x0380;
const GICD_ICACTIVER_END: u64 = 0x03FC;
const GICD_IPRIORITYR_BASE: u64 = 0x0400; // §12.9.11
const GICD_IPRIORITYR_END: u64 = 0x07F8;
const GICD_ICFGR_BASE: u64 = 0x0C00; // §12.9.12
const GICD_ICFGR_END: u64 = 0x0CFC;
const GICD_IROUTER_BASE: u64 = 0x6100; // §12.9.13
const GICD_IROUTER_END: u64 = 0x7FD8;
const GICD_PIDR2: u64 = 0xFFE8; // §12.9.20

/// Distributor IIDR identifier — ARM Limited (JEP106 0x43B), product 0x0,
/// variant 0, revision 0. Linux vgic-v3 uses an analogous constant in
/// vgic-mmio-v3.c (vgic_mmio_read_v3_misc). GICv3 §12.9.6.
const GICD_IIDR_VALUE: u32 = 0x0043B;

/// PIDR2 ArchRev field for GICv3 = 3, in bits [7:4]. GICv3 §12.9.20.
const PIDR2_GICV3: u32 = 0x30;

// ===========================================================================
// GICR register offsets (GICv3 §12.10 Redistributor register summary)
// ===========================================================================
//
// A GICv3 redistributor is two consecutive 64K frames:
//   RD_base   (offset 0x00000)  — control + LPI tables
//   SGI_base  (offset 0x10000)  — per-vCPU SGI/PPI state
//
// Within RD_base:
//   GICR_CTLR    0x0000
//   GICR_IIDR    0x0004
//   GICR_TYPER   0x0008  (8-byte register; supports 4 and 8-byte access)
//   GICR_WAKER   0x0014
//   GICR_PIDR2   0xFFE8
//
// Within SGI_base (offsets relative to RD_base + 0x10000):
//   GICR_IGROUPR0     0x0080  bits[31:0] = group bit per INTID 0..31
//   GICR_ISENABLER0   0x0100
//   GICR_ICENABLER0   0x0180
//   GICR_ISPENDR0     0x0200
//   GICR_ICPENDR0     0x0280
//   GICR_ISACTIVER0   0x0300
//   GICR_ICACTIVER0   0x0380
//   GICR_IPRIORITYR0  0x0400  (32 bytes)
//   GICR_ICFGR0       0x0C00  (SGIs)
//   GICR_ICFGR1       0x0C04  (PPIs)

const GICR_CTLR: u64 = 0x0000;
const GICR_IIDR: u64 = 0x0004;
const GICR_TYPER: u64 = 0x0008;
const GICR_WAKER: u64 = 0x0014;
const GICR_PIDR2: u64 = 0xFFE8;

const GICR_SGI_IGROUPR0: u64 = 0x10080;
const GICR_SGI_ISENABLER0: u64 = 0x10100;
const GICR_SGI_ICENABLER0: u64 = 0x10180;
const GICR_SGI_ISPENDR0: u64 = 0x10200;
const GICR_SGI_ICPENDR0: u64 = 0x10280;
const GICR_SGI_ISACTIVER0: u64 = 0x10300;
const GICR_SGI_ICACTIVER0: u64 = 0x10380;
const GICR_SGI_IPRIORITYR_BASE: u64 = 0x10400;
const GICR_SGI_IPRIORITYR_END: u64 = 0x1041C;
const GICR_SGI_ICFGR0: u64 = 0x10C00;
const GICR_SGI_ICFGR1: u64 = 0x10C04;

// ===========================================================================
// GICD_CTLR / GICR_CTLR / GICR_WAKER bits
// ===========================================================================

/// GICD_CTLR.ARE_NS — Affinity Routing Enable for non-secure state.
/// We force-enable this bit because the vGIC always operates in
/// affinity-routed mode. GICv3 §12.9.4.
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// GICD_CTLR.EnableGrp1NS — guests are non-secure. GICv3 §12.9.4.
const GICD_CTLR_ENABLE_GRP1NS: u32 = 1 << 1;
/// GICD_CTLR.RWP — register write pending. GICv3 §12.9.4 bit 31. We
/// always report 0 (writes complete synchronously).
const GICD_CTLR_RWP: u32 = 1 << 31;

/// GICR_WAKER.ProcessorSleep — bit 1. GICv3 §12.10.21.
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// GICR_WAKER.ChildrenAsleep — bit 2. GICv3 §12.10.21.
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// ===========================================================================
// ICH_LR<n>_EL2 list register encoding (GICv3 §12.5.10, ARM ARM D13.8.51)
// ===========================================================================
//
// Bit layout of a 64-bit ICH_LR<n>_EL2 entry:
//   [31:0]    vINTID    — virtual interrupt ID
//   [41:32]   pINTID    — physical INTID for HW interrupts (HW=1 only)
//   [47:32]   EOI       — bit 41 in the GICv4 layout (reserved when HW=1)
//                         For SW interrupts this is the "EOI" bit (41).
//   [55:48]   Priority  — virtual priority, 0=highest
//   [60:58]   Group     — 0 = Group 0, 1 = Group 1
//   [61]      HW        — 1 = forwarded HW interrupt (we always emit 0)
//   [63:62]   State     — 00 invalid, 01 pending, 10 active, 11 active+pending
//
// Linux: include/linux/irqchip/arm-gic-v3.h ICH_LR_* constants.

const LR_VINTID_MASK: u64 = 0xFFFFFFFF;
const LR_EOI_BIT: u64 = 1 << 41;
const LR_PRIORITY_SHIFT: u6 = 48;
const LR_PRIORITY_MASK: u64 = 0xFF << LR_PRIORITY_SHIFT;
const LR_GROUP_BIT: u64 = 1 << 60;
const LR_HW_BIT: u64 = 1 << 61;
const LR_STATE_SHIFT: u6 = 62;
const LR_STATE_MASK: u64 = @as(u64, 0b11) << LR_STATE_SHIFT;
const LR_STATE_INVALID: u64 = 0b00 << LR_STATE_SHIFT;
const LR_STATE_PENDING: u64 = 0b01 << LR_STATE_SHIFT;
const LR_STATE_ACTIVE: u64 = 0b10 << LR_STATE_SHIFT;
const LR_STATE_ACTIVE_PENDING: u64 = 0b11 << LR_STATE_SHIFT;

// ===========================================================================
// ICH_HCR_EL2 control bits (GICv3 §12.5.7, ARM ARM D13.8.45)
// ===========================================================================

/// ICH_HCR_EL2.En — global enable for the virtual CPU interface.
const ICH_HCR_EN: u64 = 1 << 0;
/// ICH_HCR_EL2.UIE — Underflow Interrupt Enable. Maintenance IRQ when
/// 0 or 1 list registers are non-invalid. GICv3 §12.5.7 bit 1.
const ICH_HCR_UIE: u64 = 1 << 1;
/// ICH_HCR_EL2.LRENPIE — List Register Entry Not Present Interrupt Enable.
/// Maintenance IRQ when EOImode==1 and a write to ICC_DIR_EL1 has no
/// matching active LR (we handle EOI in software for SW-injected IRQs).
const ICH_HCR_LRENPIE: u64 = 1 << 2;
/// ICH_HCR_EL2.NPIE — No-Pending Interrupt Enable. Maintenance IRQ when
/// no LR is in pending state. GICv3 §12.5.7 bit 3.
const ICH_HCR_NPIE: u64 = 1 << 3;
/// ICH_HCR_EL2.VGrp1EIE / VGrp1DIE — group 1 enable change MIs. We do not
/// use them.

// ===========================================================================
// Per-INTID state bitmaps
// ===========================================================================
//
// GICv3 §4.5 "Interrupt handling state machine" defines four states per
// INTID: inactive, pending, active, active+pending. We track these with
// independent enable / pending / active / config bitmaps because that is
// also how Linux's vgic core represents them (see struct vgic_irq in
// arch/arm64/kvm/vgic/vgic.h) — one bit per INTID is enough since the
// active/pending product uniquely determines the state.

/// Number of u32 words to cover `n` bits, rounded up.
fn bitmapWords(n: u32) u32 {
    return (n + 31) >> 5;
}

const SPI_BITMAP_WORDS: u32 = bitmapWords(MAX_SPIS);

inline fn bitSet(words: []u32, bit: u32) void {
    const w = bit >> 5;
    const b: u5 = @intCast(bit & 0x1F);
    words[w] |= @as(u32, 1) << b;
}

inline fn bitClear(words: []u32, bit: u32) void {
    const w = bit >> 5;
    const b: u5 = @intCast(bit & 0x1F);
    words[w] &= ~(@as(u32, 1) << b);
}

inline fn bitTest(words: []const u32, bit: u32) bool {
    const w = bit >> 5;
    const b: u5 = @intCast(bit & 0x1F);
    return (words[w] & (@as(u32, 1) << b)) != 0;
}

// ===========================================================================
// Per-VM Vgic state (the distributor)
// ===========================================================================

/// Per-VM vGIC state. Mirrors the role of x64 lapic.Lapic + ioapic.Ioapic
/// combined: holds distributor SPI bookkeeping and exposes MMIO decode for
/// GICD_BASE..GICD_BASE+GICD_SIZE. SGI/PPI state lives in `VcpuState`
/// because GICv3 §9.4 makes the redistributor (i.e. per-vCPU) the owner
/// of those INTIDs.
pub const Vgic = struct {
    /// Lock guarding all distributor bitmaps and config arrays. Held
    /// across MMIO decode and SPI assertion. Linux uses an irq_lock per
    /// vgic_irq plus a dist lock; we serialise the entire distributor
    /// for simplicity, which is fine for the small SPI counts we cap to.
    lock: SpinLock = .{},

    /// GICD_CTLR shadow (only ARE_NS + EnableGrp1NS bits are meaningful;
    /// the rest are RAZ/WI). GICv3 §12.9.4.
    ctlr: u32 = 0,

    /// SPI enable bitmap (1 bit per SPI; bit n covers INTID n+32).
    /// GICv3 §12.9.7 GICD_ISENABLER / §12.9.8 GICD_ICENABLER.
    spi_enabled: [SPI_BITMAP_WORDS]u32 = .{0} ** SPI_BITMAP_WORDS,

    /// SPI pending bitmap. GICv3 §12.9.9 GICD_ISPENDR / §4.5 state machine.
    spi_pending: [SPI_BITMAP_WORDS]u32 = .{0} ** SPI_BITMAP_WORDS,

    /// SPI active bitmap. Updated by saveExit when an LR transitions out
    /// of the active state. GICv3 §12.9 GICD_ISACTIVER / §4.5.
    spi_active: [SPI_BITMAP_WORDS]u32 = .{0} ** SPI_BITMAP_WORDS,

    /// SPI level-asserted bitmap (input from assertSpi/deassertSpi for
    /// level-triggered lines). For edge-triggered lines this is unused
    /// (assertion just sets pending). GICv3 §4.5.2.
    spi_level: [SPI_BITMAP_WORDS]u32 = .{0} ** SPI_BITMAP_WORDS,

    /// SPI configuration: 0 = level-sensitive, 1 = edge-triggered.
    /// GICv3 §12.9.12 GICD_ICFGR. Two bits per INTID in hardware, but
    /// only bit[1] is writable; we store one bit per SPI here.
    spi_edge: [SPI_BITMAP_WORDS]u32 = .{0} ** SPI_BITMAP_WORDS,

    /// SPI group: 0 = Group 0, 1 = Group 1. GICv3 §12.9.10 GICD_IGROUPR.
    /// Linux defaults all SPIs to Group 1 (non-secure) and we follow
    /// suit; vgic-mmio-v3.c vgic_mmio_read_group / write_group.
    spi_group: [SPI_BITMAP_WORDS]u32 = .{0xFFFFFFFF} ** SPI_BITMAP_WORDS,

    /// Per-SPI 8-bit priority. GICv3 §12.9.11 GICD_IPRIORITYR.
    spi_priority: [MAX_SPIS]u8 = .{0xA0} ** MAX_SPIS,

    /// Per-SPI routing (affinity). GICv3 §12.9.13 GICD_IROUTER.
    /// Encodes Aff3.Aff2.Aff1.Aff0 in bits [39:0] + Interrupt_Routing_Mode
    /// in bit 31. We honour this only as a vCPU index lookup at injection
    /// time (Aff0 → vCPU index for our flat affinity layout).
    spi_router: [MAX_SPIS]u64 = .{0} ** MAX_SPIS,

    /// Number of vCPUs in the owning VM. Set by `init`. Used for
    /// redistributor TYPER.Last bit and routing decode.
    num_vcpus: u32 = 0,
};

// ===========================================================================
// Per-vCPU VcpuState (the redistributor + LR shadow)
// ===========================================================================

/// Per-vCPU vGIC state. Holds:
///   - Redistributor SGI/PPI bookkeeping (GICv3 §9.4).
///   - The list-register shadow that prepareEntry / saveExit flush to and
///     from ICH_LR<n>_EL2.
///   - The cached ICH_HCR_EL2 / ICH_VMCR_EL2 control values (set by init,
///     mutated by maintenance interrupts).
pub const VcpuState = struct {
    /// vCPU index inside the owning VM (0..num_vcpus-1). Used to derive
    /// the redistributor base address and to compare against SPI routing.
    vcpu_index: u32 = 0,

    /// Pointer back to the owning Vm's Vgic. Set by init.
    dist: *Vgic = undefined,

    /// Per-vCPU lock guarding the SGI/PPI bitmaps and the LR shadow.
    /// Held across mmioRead/mmioWrite for any GICR access targeting this
    /// vCPU and across prepareEntry/saveExit.
    lock: SpinLock = .{},

    /// SGI/PPI enable bitmap (one u32 covers INTIDs 0..31). GICv3 §9.4.
    sgi_ppi_enabled: u32 = 0xFFFF, // SGIs reset enabled per §9.4.6.
    /// SGI/PPI pending bitmap.
    sgi_ppi_pending: u32 = 0,
    /// SGI/PPI active bitmap.
    sgi_ppi_active: u32 = 0,
    /// SGI/PPI group (0 = Grp0, 1 = Grp1). Default Grp1 (non-secure).
    sgi_ppi_group: u32 = 0xFFFFFFFF,
    /// SGI/PPI configuration: 0 = level, 1 = edge. SGIs are always edge
    /// (GICv3 §9.4.12) so bits[15:0] are RAO/WI in the spec view. PPIs
    /// default to level-sensitive on most SoCs.
    sgi_ppi_edge: u32 = 0xFFFF,
    /// Per-INTID 8-bit priority (32 INTIDs).
    sgi_ppi_priority: [NUM_SGI_PPI]u8 = .{0xA0} ** NUM_SGI_PPI,

    /// GICR_CTLR shadow (we expose the EnableLPI bit only; LPIs are not
    /// implemented). GICv3 §12.10.10.
    gicr_ctlr: u32 = 0,
    /// GICR_WAKER shadow. The guest writes ProcessorSleep=0 then waits for
    /// ChildrenAsleep=0; we honour the protocol synchronously.
    /// GICv3 §12.10.21.
    gicr_waker: u32 = GICR_WAKER_PROCESSOR_SLEEP | GICR_WAKER_CHILDREN_ASLEEP,

    /// List-register shadow. lrs[i] mirrors ICH_LR<i>_EL2 between
    /// prepareEntry and saveExit. Indices >= num_lrs are unused.
    /// GICv3 §11.2 / §12.5.10.
    lrs: [MAX_LRS]u64 = .{0} ** MAX_LRS,

    /// ICH_HCR_EL2 cached control bits. GICv3 §12.5.7.
    hcr: u64 = ICH_HCR_EN,

    /// ICH_VMCR_EL2 — virtual machine control: PMR / BPR / EOImode etc.
    /// GICv3 §12.5.27. Default value gives the guest a Group 1 enabled
    /// virtual CPU interface with PMR=0xF8 (matches Linux KVM init).
    vmcr: u64 = 0xF800_0002,

    /// ICH_AP0R0_EL2 shadow — Group 0 Active Priorities Register 0.
    /// GICv3 §12.5.2 / ARM ARM D13.8.42. Saved on exit / loaded on
    /// entry so the virtual CPU interface preserves its active priority
    /// stack across world switches. For GICv3 with 5 priority bits
    /// (the architectural minimum) only AP{0,1}R0 exist; wider
    /// priorities spill into AP{0,1}R{1,2,3}. We start with R0 only
    /// which matches the Pi 5 / QEMU configuration.
    ap0r0: u64 = 0,

    /// ICH_AP1R0_EL2 shadow — Group 1 Active Priorities Register 0.
    /// GICv3 §12.5.5 / ARM ARM D13.8.46.
    ap1r0: u64 = 0,

    /// True after saveExit has observed a maintenance interrupt that
    /// must be processed by the next prepareEntry (refill LRs from the
    /// pending bitmaps).
    needs_refill: bool = false,

    /// EL2 sysreg shadow buffer handed to the hyp stubs. Lives in the
    /// vcpu struct (slab-allocated, physmap-resident) so its VA→PA can
    /// be cheaply resolved via `PAddr.fromVAddr`. EL2 runs with
    /// SCTLR_EL2.M=0, so the stubs dereference this buffer as a PA —
    /// a stack-local VA would fault the first time the stub does
    /// `ldr x2, [x1, ...]`.
    hw_shadow: VcpuHwShadow align(16) = .{},
};

/// EL2 sysreg shadow handed to the `hvc_vgic_prepare_entry` /
/// `hvc_vgic_save_exit` hyp stubs. `extern struct` with hardcoded
/// field offsets because the stub uses `ldr/str [x1, #IMM]`.
///
/// The stubs always load/store all 16 LR slots — slots beyond
/// `num_lrs` are left zero (LR.State = 0b00 Invalid, GICv3 §11.2.5,
/// which is "no pending/active entry") so they are architecturally
/// harmless.
pub const VcpuHwShadow = extern struct {
    /// ICH_LR0..15_EL2 (ARM ARM D13.8.51, Table D13-65).
    lrs: [MAX_LRS]u64 = .{0} ** MAX_LRS,
    /// ICH_HCR_EL2 value to load. Caller forces EN=1 before hvc.
    /// GICv3 §12.5.7.
    hcr: u64 = 0,
    /// ICH_VMCR_EL2 (GICv3 §12.5.27).
    vmcr: u64 = 0,
    /// ICH_AP0R0_EL2 (GICv3 §12.5.2 / ARM ARM D13.8.42).
    ap0r0: u64 = 0,
    /// ICH_AP1R0_EL2 (GICv3 §12.5.5 / ARM ARM D13.8.46).
    ap1r0: u64 = 0,
    /// ICH_MISR_EL2 snapshot written by `hvc_vgic_save_exit` (ARM ARM
    /// D13.8.47). Only consumed on exit — ignored by the entry stub.
    misr: u64 = 0,
    /// Number of implemented list registers on this host (1..16). Read
    /// by `hvc_vgic_prepare_entry` / `hvc_vgic_save_exit` to decide how
    /// many ICH_LR<n>_EL2 slots to touch — writing or reading an
    /// unimplemented LR sysreg is UNDEFINED on GICv3 hosts that report
    /// ICH_VTR_EL2.ListRegs < 15 (e.g. cortex-a72 TCG with 4 LRs).
    /// Caller (prepareEntry/saveExit) must populate this before the hvc.
    num_lrs: u64 = 16,
};

comptime {
    std.debug.assert(@offsetOf(VcpuHwShadow, "lrs") == 0x00);
    std.debug.assert(@offsetOf(VcpuHwShadow, "hcr") == 0x80);
    std.debug.assert(@offsetOf(VcpuHwShadow, "vmcr") == 0x88);
    std.debug.assert(@offsetOf(VcpuHwShadow, "ap0r0") == 0x90);
    std.debug.assert(@offsetOf(VcpuHwShadow, "ap1r0") == 0x98);
    std.debug.assert(@offsetOf(VcpuHwShadow, "misr") == 0xA0);
    std.debug.assert(@offsetOf(VcpuHwShadow, "num_lrs") == 0xA8);
    std.debug.assert(MAX_LRS == 16);
}

// ===========================================================================
// Host capability detection
// ===========================================================================

/// Number of list registers actually implemented on this host CPU. Set
/// by `init` from ICH_VTR_EL2.ListRegs. Cached globally because ICH_VTR
/// is identical across cores in any sane SoC and this avoids re-reading
/// it on every prepareEntry.
///
/// GICv3 §12.5.30 ICH_VTR_EL2 bits [4:0] = ListRegs - 1.
var num_lrs: u8 = 4;

/// True after `detectListRegs` has probed ICH_VTR_EL2 at least once.
/// Prevents the probe from re-running on every per-VM `init`.
var list_regs_detected: bool = false;

/// Detect how many list registers the host implements by reading
/// ICH_VTR_EL2.ListRegs (bits[4:0], the encoded count is ListRegs-1).
///
/// GICv3 §12.5.30 / ARM ARM D13.8.50: ICH_VTR_EL2 is EL2-only, so an
/// EL1 `mrs` traps. The kernel runs at EL1 and this function is
/// called from `vgic.init` on `vmCreate`; we therefore forward the
/// probe through `hvc_vgic_detect_lrs` which reads the sysreg at EL2
/// and returns `(ICH_VTR_EL2.ListRegs + 1)` in x0. If the stub ever
/// returns 0 or a count larger than MAX_LRS we fall back to the
/// architectural minimum of 4 list registers (GICv3 §11.2.5) which
/// is also what the Pi 5 Cortex-A76 and QEMU virt implement.
fn detectListRegs() void {
    if (list_regs_detected) return;
    list_regs_detected = true;
    const count_u64: u64 = vm_hw.hypCall(.vgic_detect_lrs, 0);
    const count: u8 = @intCast(count_u64 & 0xFF);
    if (count == 0 or count > MAX_LRS) {
        // Sanity clamp: a zero/oversized read means the sysreg
        // was unavailable or returned garbage; fall back to the
        // spec minimum.
        num_lrs = 4;
        return;
    }
    num_lrs = count;
}

/// Public accessor for `num_lrs`, exposed so vcpu / test code can
/// observe the detected list register count without reaching into
/// the private module variable.
pub fn listRegCount() u8 {
    return num_lrs;
}

// ===========================================================================
// Initialization
// ===========================================================================

/// Initialize per-VM vGIC distributor state. Called by `kvm.vm.vmCreate`
/// after the Vm struct is allocated but before vCPU creation.
///
/// Resets the distributor to a Linux-compatible power-on state:
///   - GICD_CTLR.ARE_NS forced 1 (we only support affinity-routed mode).
///   - All SPIs disabled, inactive, not pending.
///   - All SPIs default to Group 1 (non-secure) and priority 0xA0.
///
/// Reference: GICv3 §12.9, Linux arch/arm64/kvm/vgic/vgic-init.c
/// kvm_vgic_dist_init.
pub fn init(vgic: *Vgic, num_vcpus: u32) void {
    vgic.* = .{};
    vgic.ctlr = GICD_CTLR_ARE_NS;
    vgic.num_vcpus = num_vcpus;
    detectListRegs();
}

/// Initialize per-vCPU vGIC state. Called by vcpu.create after the
/// VCpu struct is allocated.
///
/// Reference: GICv3 §9.4, Linux vgic-init.c kvm_vgic_vcpu_init.
pub fn initVcpu(state: *VcpuState, dist: *Vgic, vcpu_index: u32) void {
    state.* = .{};
    state.dist = dist;
    state.vcpu_index = vcpu_index;
}

// ===========================================================================
// Public injection API
// ===========================================================================

/// Assert an SPI line (INTID 32..MAX_SPIS+31). Called by
/// `kvm.vm.intcAssertIrq`, which is the cross-arch `vm_intc_assert_irq`
/// syscall dispatched to the aarch64 backend.
///
/// Sets the pending state in the distributor for the given INTID. The
/// caller is responsible for kicking the targeted vCPU if it is currently
/// running so the new pending state takes effect on the next entry —
/// this function does not perform IPIs because it has no view of the
/// vCPU run-state lock. The intended call sequence is:
///
///   vgic.assertSpi(...);
///   vm_obj.kickRunningVcpus();   // implemented in kvm/vm.zig
///
/// Reference: GICv3 §4.5 "Interrupt handling state machine" — assertion
/// of an inactive INTID transitions it to "pending"; assertion of an
/// already-active level-sensitive INTID transitions it to "active+pending"
/// (handled via the spi_level bookkeeping).
pub fn assertSpi(vgic: *Vgic, intid: u32) void {
    if (intid < 32) return;
    const spi: u32 = intid - 32;
    if (spi >= MAX_SPIS) return;

    const flags = vgic.lock.lockIrqSave();
    defer vgic.lock.unlockIrqRestore(flags);

    if (bitTest(&vgic.spi_edge, spi)) {
        // Edge-triggered: every assertion latches a new pending. The
        // GICv3 §4.5.1 "Edge-triggered interrupts" rule says repeated
        // edges on an already-pending INTID are coalesced.
        bitSet(&vgic.spi_pending, spi);
    } else {
        // Level-triggered: pending tracks the input line.
        // GICv3 §4.5.2 "Level-sensitive interrupts".
        bitSet(&vgic.spi_level, spi);
        bitSet(&vgic.spi_pending, spi);
    }
}

/// De-assert an SPI line. For edge-triggered SPIs this is a no-op (the
/// interrupt has already been latched into pending); for level-sensitive
/// SPIs this clears the pending-from-input state.
///
/// Reference: GICv3 §4.5.2.
pub fn deassertSpi(vgic: *Vgic, intid: u32) void {
    if (intid < 32) return;
    const spi: u32 = intid - 32;
    if (spi >= MAX_SPIS) return;

    const flags = vgic.lock.lockIrqSave();
    defer vgic.lock.unlockIrqRestore(flags);

    if (bitTest(&vgic.spi_edge, spi)) return;
    bitClear(&vgic.spi_level, spi);
    // Only clear the pending bit if the INTID is not currently active in
    // a list register; clearing pending while active would lose the EOI
    // bookkeeping. The active-pending → active transition happens via
    // saveExit when the guest acks; we just need to drop the *future*
    // re-pending here. Linux: vgic.c vgic_validate_injection.
    if (!bitTest(&vgic.spi_active, spi)) {
        bitClear(&vgic.spi_pending, spi);
    }
}

/// Inject a virtual interrupt directly into a vCPU. Used by
/// vm_vcpu_interrupt, which carries an explicit GuestInterrupt payload.
///
/// For SPIs this just feeds assertSpi; for SGI/PPI it sets the
/// per-vCPU pending bit so the next prepareEntry can fill an LR.
///
/// Reference: GICv3 §11.2 "List registers", ARM ARM D13.8.51
/// ICH_LR<n>_EL2.
pub fn injectInterrupt(vcpu_state: *VcpuState, interrupt: vm_hw.GuestInterrupt) void {
    const intid = interrupt.intid;
    if (intid >= 32) {
        assertSpi(vcpu_state.dist, intid);
        return;
    }

    const flags = vcpu_state.lock.lockIrqSave();
    defer vcpu_state.lock.unlockIrqRestore(flags);

    // SGI / PPI — just latch the pending bit. Priority comes from the
    // redistributor IPRIORITYR entry, not from the GuestInterrupt
    // (matching Linux: arch/arm64/kvm/vgic/vgic-irqfd.c).
    vcpu_state.sgi_ppi_pending |= (@as(u32, 1) << @as(u5, @intCast(intid)));
    _ = interrupt.priority;
    _ = interrupt.kind;
}

// ===========================================================================
// LR allocation helpers
// ===========================================================================

/// Find a free list register slot in the shadow array. Returns null if
/// every LR currently holds a non-invalid entry.
///
/// "Free" means state == invalid (00). Linux's policy in
/// vgic.c __vgic_v3_populate_lr is the same: walk LRs, look for
/// state==INVALID, and if none are free, evict by setting NPIE so the
/// next maintenance IRQ refills.
fn allocLr(state: *VcpuState) ?u8 {
    var i: u8 = 0;
    while (i < num_lrs) {
        if ((state.lrs[i] & LR_STATE_MASK) == LR_STATE_INVALID) return i;
        i += 1;
    }
    return null;
}

/// Build an ICH_LR<n>_EL2 entry for a software-injected interrupt.
/// HW=0 (always — this implementation never forwards a host hardware
/// IRQ to a guest), Group=1, EOI=1 so we receive a maintenance
/// interrupt on guest EOI for SW INTIDs in EOImode==1.
///
/// Reference: GICv3 §12.5.10, Linux include/linux/irqchip/arm-gic-v3.h
/// ICH_LR_* construction.
fn buildLrEntry(intid: u32, priority: u8) u64 {
    var lr: u64 = 0;
    lr |= @as(u64, intid) & LR_VINTID_MASK;
    lr |= @as(u64, priority) << LR_PRIORITY_SHIFT;
    lr |= LR_GROUP_BIT;
    lr |= LR_EOI_BIT;
    lr |= LR_STATE_PENDING;
    return lr;
}

/// Walk the per-vCPU SGI/PPI pending bits and the distributor SPI
/// pending bits and refill empty LRs. Honours enable masks and per-INTID
/// active state to avoid re-injecting an already-active INTID.
///
/// Called from prepareEntry. Linux equivalent: vgic-v3.c vgic_v3_flush_hwstate.
fn refillLrsLocked(state: *VcpuState, dist: *Vgic) void {
    // Pass 1: SGI/PPI. These are the highest-priority candidates because
    // they often carry the timer/IPI on Linux guests.
    var pending = state.sgi_ppi_pending & state.sgi_ppi_enabled & ~state.sgi_ppi_active;
    while (pending != 0) {
        const slot = allocLr(state) orelse {
            // Out of LRs — request a no-pending maintenance IRQ so we
            // are notified the moment a slot frees up.
            state.hcr |= ICH_HCR_NPIE;
            return;
        };
        const intid: u5 = @intCast(@ctz(pending));
        pending &= pending - 1;
        state.lrs[slot] = buildLrEntry(intid, state.sgi_ppi_priority[intid]);
        // Move from pending → in-flight (LR holds the pending bit now).
        state.sgi_ppi_pending &= ~(@as(u32, 1) << intid);
    }

    // Pass 2: SPIs from the distributor. Take the lock briefly.
    const dflags = dist.lock.lockIrqSave();
    defer dist.lock.unlockIrqRestore(dflags);

    var word: u32 = 0;
    while (word < SPI_BITMAP_WORDS) {
        var bits = dist.spi_pending[word] & dist.spi_enabled[word] & ~dist.spi_active[word];
        while (bits != 0) {
            const slot = allocLr(state) orelse {
                state.hcr |= ICH_HCR_NPIE;
                return;
            };
            const lsb: u5 = @intCast(@ctz(bits));
            bits &= bits - 1;
            const spi = (word << 5) + lsb;
            if (spi >= MAX_SPIS) break;
            const intid: u32 = spi + 32;

            // Routing: only deliver if this vCPU is the targeted Aff0.
            // GICv3 §12.9.13 GICD_IROUTER. We model the single-affinity
            // case (Aff3.2.1 = 0) used by Linux KVM.
            const router = dist.spi_router[spi];
            const irm = (router >> 31) & 1;
            const target_aff0: u32 = @intCast(router & 0xFF);
            if (irm == 0 and target_aff0 != state.vcpu_index) continue;

            state.lrs[slot] = buildLrEntry(intid, dist.spi_priority[spi]);
            bitClear(&dist.spi_pending, spi);
            bitSet(&dist.spi_active, spi); // tentative; cleared by EOI MI
        }
        word += 1;
    }
}

// ===========================================================================
// Entry / exit hooks
// ===========================================================================

/// Called by the vCPU run loop just before `vm_hyp.vmResume`. Refills
/// the LR shadow from the distributor / redistributor pending bitmaps,
/// then writes the shadow into ICH_LR<n>_EL2 and ICH_HCR_EL2.
///
/// Reference: GICv3 §11.2 list registers, §12.5 system register interface,
/// Linux vgic-v3.c vgic_v3_flush_hwstate.
pub fn prepareEntry(state: *VcpuState) void {
    const flags = state.lock.lockIrqSave();
    defer state.lock.unlockIrqRestore(flags);

    refillLrsLocked(state, state.dist);

    // Gather the EL2-sysreg-bound state into a pinned-layout shadow
    // and hand it to the `hvc_vgic_prepare_entry` stub. All ICH_*_EL2
    // registers are EL2-only (ARM ARM D13.8) so the EL1 kernel cannot
    // write them directly. GICv3 §11.4 "Maintenance interrupts" notes
    // that enabling the interface before LRs are populated can cause
    // a spurious underflow MI, so the stub writes LRs / AP / VMCR
    // first and enables the CPU interface (ICH_HCR_EL2.EN) last.
    const shadow = &state.hw_shadow;
    shadow.* = .{};
    shadow.lrs = state.lrs;
    shadow.hcr = state.hcr | ICH_HCR_EN;
    shadow.vmcr = state.vmcr;
    shadow.ap0r0 = state.ap0r0;
    shadow.ap1r0 = state.ap1r0;
    shadow.num_lrs = num_lrs;
    // EL2 runs with SCTLR_EL2.M=0 (no stage-1), so the stub dereferences
    // the shadow pointer as a PA. The slab-allocated VCpu lives in the
    // kernel heap partition (not physmap) so we must page-walk to turn
    // the kernel VA into a PA.
    const shadow_pa = shadowKernelPA(@intFromPtr(shadow));
    _ = vm_hw.hypCall(.vgic_prepare_entry, shadow_pa);
}

/// Called by the vCPU run loop immediately after `vm_hyp.vmResume`
/// returns. Snapshots ICH_LR<n>_EL2 back into the shadow state and
/// records active→inactive transitions (the guest acked an SPI) by
/// clearing the corresponding spi_active bit.
///
/// Also reads ICH_MISR_EL2 / ICH_EISR_EL2 to detect EOI maintenance
/// interrupts and re-pending of level-sensitive lines.
///
/// Reference: GICv3 §11.4 maintenance interrupts, §11.5 EOI handling,
/// Linux vgic-v3.c vgic_v3_fold_lr_state.
pub fn saveExit(state: *VcpuState) void {
    const flags = state.lock.lockIrqSave();
    defer state.lock.unlockIrqRestore(flags);

    // Snapshot ICH_LR*_EL2 / ICH_AP{0,1}R0_EL2 at EL2 via the
    // `hvc_vgic_save_exit` stub, which also disables the virtual CPU
    // interface (ICH_HCR_EL2 ← 0) for the host-running window so a
    // maintenance IRQ cannot fire into the host (GICv3 §12.5.7 "En").
    // EL1 cannot read these sysregs directly (ARM ARM D13.8).
    const shadow = &state.hw_shadow;
    shadow.lrs = state.lrs;
    shadow.num_lrs = num_lrs;
    // See prepareEntry — EL2 has no stage-1, the stub dereferences a PA.
    const shadow_pa = shadowKernelPA(@intFromPtr(shadow));
    _ = vm_hw.hypCall(.vgic_save_exit, shadow_pa);
    state.lrs = shadow.lrs;
    state.ap0r0 = shadow.ap0r0;
    state.ap1r0 = shadow.ap1r0;

    // Walk the LR shadow looking for entries that have transitioned out
    // of active or pending state. The hardware updates the state field
    // in-place when the guest IARs / EOIs the interrupt; we mirror those
    // transitions back into the distributor / redistributor bookkeeping.
    var i: u8 = 0;
    while (i < num_lrs) : (i += 1) {
        const lr = state.lrs[i];
        if ((lr & LR_STATE_MASK) == LR_STATE_INVALID) continue;
        const intid: u32 = @intCast(lr & LR_VINTID_MASK);
        const lr_state = lr & LR_STATE_MASK;

        if (lr_state == LR_STATE_INVALID) {
            // Entry was consumed (guest IAR + EOI). Clear active state.
            clearActiveState(state, intid);
            state.lrs[i] = 0;
        } else if (lr_state == LR_STATE_PENDING) {
            // The HW marked it pending without consuming → guest hasn't
            // acked yet. Leave it alone; next prepareEntry will rewrite.
        } else if (lr_state == LR_STATE_ACTIVE_PENDING) {
            // Re-fired while still active (level-sensitive line). Mark
            // pending in the distributor so the next entry sees it.
            // GICv3 §4.5.2.
            if (intid >= 32) {
                const spi = intid - 32;
                if (spi < MAX_SPIS) {
                    const dflags = state.dist.lock.lockIrqSave();
                    bitSet(&state.dist.spi_pending, spi);
                    state.dist.lock.unlockIrqRestore(dflags);
                }
            } else {
                state.sgi_ppi_pending |= (@as(u32, 1) << @as(u5, @intCast(intid)));
            }
        }
    }

    // If MISR.U is set the host is telling us LRs are nearly empty;
    // schedule a refill on the next prepareEntry. GICv3 §12.5.18.
    // ICH_MISR_EL2 is EL2-only (ARM ARM D13.8.47) so we read the
    // snapshot the `hvc_vgic_save_exit` stub stashed in the shadow.
    const misr = shadow.misr;
    if ((misr & 0b1) != 0) {
        // EOI maintenance — already handled by walking LRs above.
    }
    if ((misr & 0b10) != 0) {
        state.needs_refill = true;
    }

    // Clear NPIE; prepareEntry will re-set it if it cannot fit
    // everything. Avoids a tight maintenance IRQ storm.
    state.hcr &= ~ICH_HCR_NPIE;

    // Note: ICH_HCR_EL2 ← 0 is issued inside `hvc_vgic_save_exit`
    // after the LR/AP snapshot. GICv3 §12.5.7 ICH_HCR_EL2.En.
}

fn clearActiveState(state: *VcpuState, intid: u32) void {
    if (intid < 32) {
        state.sgi_ppi_active &= ~(@as(u32, 1) << @as(u5, @intCast(intid)));
        return;
    }
    const spi = intid - 32;
    if (spi >= MAX_SPIS) return;
    const dflags = state.dist.lock.lockIrqSave();
    defer state.dist.lock.unlockIrqRestore(dflags);
    bitClear(&state.dist.spi_active, spi);
    // If the line is still asserted (level-sensitive), re-pend it so
    // the next prepareEntry injects it again. GICv3 §4.5.2.
    if (!bitTest(&state.dist.spi_edge, spi) and bitTest(&state.dist.spi_level, spi)) {
        bitSet(&state.dist.spi_pending, spi);
    }
}

/// Maintenance IRQ handler. Called from the kernel's EL1 IRQ path when
/// ICH_HCR_EL2 maintenance interrupts fire while a guest is running.
///
/// In v1 we just set `needs_refill` and let the next saveExit (which
/// runs unconditionally on every exit) drive the state machine. The
/// presence of this hook lets the IRQ path avoid a panic on the
/// maintenance INTID.
///
/// Reference: GICv3 §11.4 Maintenance interrupts, ARM ARM D13.8.49
/// ICH_MISR_EL2.
pub fn maintenanceIrq(state: *VcpuState) void {
    state.needs_refill = true;
}

// ===========================================================================
// MMIO decode dispatcher
// ===========================================================================

/// Handle a guest MMIO read on the GICD or GICR page. Called from the
/// stage-2 fault inline handler in `kvm/exit_handler.zig` when the
/// faulting IPA falls inside [GICD_BASE, GICD_BASE+GICD_SIZE) or any
/// per-vCPU redistributor range.
///
/// `offset` is relative to GICD_BASE for GICD accesses, or relative to
/// the targeted vCPU's GICR_BASE+stride*idx for GICR accesses. The
/// caller decides which by checking the absolute IPA against the bases;
/// here we infer from `offset` magnitude (offset < GICD_SIZE → GICD).
///
/// Reference: GICv3 §12.9 (GICD), §12.10 (GICR).
pub fn mmioRead(vgic: *Vgic, vcpu_state: *VcpuState, offset: u64, size: u8) u64 {
    if (offset < GICD_SIZE) return distRead(vgic, offset, size);
    return redistRead(vcpu_state, vgic, offset, size);
}

/// Counterpart to mmioRead for writes.
pub fn mmioWrite(vgic: *Vgic, vcpu_state: *VcpuState, offset: u64, size: u8, value: u64) void {
    if (offset < GICD_SIZE) {
        distWrite(vgic, offset, size, value);
        return;
    }
    redistWrite(vcpu_state, vgic, offset, size, value);
}

// ===========================================================================
// Distributor MMIO handlers
// ===========================================================================

/// GICv3 §12.9 distributor read decode.
fn distRead(vgic: *Vgic, offset: u64, size: u8) u64 {
    _ = size;
    const flags = vgic.lock.lockIrqSave();
    defer vgic.lock.unlockIrqRestore(flags);

    return switch (offset) {
        GICD_CTLR => @as(u64, vgic.ctlr | GICD_CTLR_ARE_NS),
        // GICD_TYPER §12.9.5: ITLinesNumber in bits[4:0] gives
        // 32*(ITLinesNumber+1) supported INTIDs. We support 32+MAX_SPIS.
        GICD_TYPER => blk: {
            const it_lines: u32 = (TOTAL_DIST_INTIDS / 32) - 1;
            // Bit 25 = MBIS=0, bit 24 = LPIS=0; CPUNumber field obsolete in v3.
            break :blk it_lines;
        },
        GICD_IIDR => GICD_IIDR_VALUE,
        GICD_TYPER2 => 0,
        GICD_STATUSR => 0,
        GICD_PIDR2 => PIDR2_GICV3,
        GICD_IGROUPR_BASE...GICD_IGROUPR_END => readSpiBitmap(&vgic.spi_group, offset - GICD_IGROUPR_BASE),
        GICD_ISENABLER_BASE...GICD_ISENABLER_END => readSpiBitmap(&vgic.spi_enabled, offset - GICD_ISENABLER_BASE),
        GICD_ICENABLER_BASE...GICD_ICENABLER_END => readSpiBitmap(&vgic.spi_enabled, offset - GICD_ICENABLER_BASE),
        GICD_ISPENDR_BASE...GICD_ISPENDR_END => readSpiBitmap(&vgic.spi_pending, offset - GICD_ISPENDR_BASE),
        GICD_ICPENDR_BASE...GICD_ICPENDR_END => readSpiBitmap(&vgic.spi_pending, offset - GICD_ICPENDR_BASE),
        GICD_ISACTIVER_BASE...GICD_ISACTIVER_END => readSpiBitmap(&vgic.spi_active, offset - GICD_ISACTIVER_BASE),
        GICD_ICACTIVER_BASE...GICD_ICACTIVER_END => readSpiBitmap(&vgic.spi_active, offset - GICD_ICACTIVER_BASE),
        GICD_IPRIORITYR_BASE...GICD_IPRIORITYR_END => readSpiPriority(vgic, offset - GICD_IPRIORITYR_BASE),
        GICD_ICFGR_BASE...GICD_ICFGR_END => readSpiCfg(vgic, offset - GICD_ICFGR_BASE),
        GICD_IROUTER_BASE...GICD_IROUTER_END => readSpiRouter(vgic, offset - GICD_IROUTER_BASE),
        else => 0,
    };
}

/// GICv3 §12.9 distributor write decode.
fn distWrite(vgic: *Vgic, offset: u64, size: u8, value: u64) void {
    _ = size;
    const flags = vgic.lock.lockIrqSave();
    defer vgic.lock.unlockIrqRestore(flags);

    switch (offset) {
        GICD_CTLR => {
            // Only EnableGrp1NS is honoured; ARE_NS is forced 1.
            vgic.ctlr = @intCast((value & GICD_CTLR_ENABLE_GRP1NS) | GICD_CTLR_ARE_NS);
        },
        GICD_TYPER, GICD_IIDR, GICD_TYPER2, GICD_PIDR2 => {}, // RO
        GICD_STATUSR => {}, // optional, we tie 0
        GICD_SETSPI_NSR => {
            // §12.9.16: writing the INTID sets pending. Used for MSI-style
            // injection from inside the guest.
            const intid: u32 = @intCast(value & 0x3FF);
            if (intid >= 32 and intid - 32 < MAX_SPIS) bitSet(&vgic.spi_pending, intid - 32);
        },
        GICD_CLRSPI_NSR => {
            const intid: u32 = @intCast(value & 0x3FF);
            if (intid >= 32 and intid - 32 < MAX_SPIS) bitClear(&vgic.spi_pending, intid - 32);
        },
        GICD_IGROUPR_BASE...GICD_IGROUPR_END => writeSpiBitmap(&vgic.spi_group, offset - GICD_IGROUPR_BASE, value, .replace),
        GICD_ISENABLER_BASE...GICD_ISENABLER_END => writeSpiBitmap(&vgic.spi_enabled, offset - GICD_ISENABLER_BASE, value, .set),
        GICD_ICENABLER_BASE...GICD_ICENABLER_END => writeSpiBitmap(&vgic.spi_enabled, offset - GICD_ICENABLER_BASE, value, .clear),
        GICD_ISPENDR_BASE...GICD_ISPENDR_END => writeSpiBitmap(&vgic.spi_pending, offset - GICD_ISPENDR_BASE, value, .set),
        GICD_ICPENDR_BASE...GICD_ICPENDR_END => writeSpiBitmap(&vgic.spi_pending, offset - GICD_ICPENDR_BASE, value, .clear),
        GICD_ISACTIVER_BASE...GICD_ISACTIVER_END => writeSpiBitmap(&vgic.spi_active, offset - GICD_ISACTIVER_BASE, value, .set),
        GICD_ICACTIVER_BASE...GICD_ICACTIVER_END => writeSpiBitmap(&vgic.spi_active, offset - GICD_ICACTIVER_BASE, value, .clear),
        GICD_IPRIORITYR_BASE...GICD_IPRIORITYR_END => writeSpiPriority(vgic, offset - GICD_IPRIORITYR_BASE, value),
        GICD_ICFGR_BASE...GICD_ICFGR_END => writeSpiCfg(vgic, offset - GICD_ICFGR_BASE, @intCast(value & 0xFFFFFFFF)),
        GICD_IROUTER_BASE...GICD_IROUTER_END => writeSpiRouter(vgic, offset - GICD_IROUTER_BASE, value),
        else => {},
    }
}

// ---------------------------------------------------------------------------
// Distributor SPI bitmap accessors
// ---------------------------------------------------------------------------
//
// GICv3 §9.6 specifies that the SPI portion of distributor bitmap registers
// (offsets ≥ register_base + 4) covers INTIDs 32..N. The SGI/PPI portion
// (the first u32 at the base) is RAZ/WI from the distributor view because
// SGI/PPI live in the redistributor. We follow that contract.

/// Read a 32-bit slice of an SPI bitmap. `byte_offset` is relative to the
/// register-base; offset 0 is GICD_*<0> (INTIDs 0..31) and is RAZ for SPI
/// bitmaps. Offsets 4, 8, … cover SPI words.
fn readSpiBitmap(words: []const u32, byte_offset: u64) u64 {
    const widx = byte_offset >> 2;
    if (widx == 0) return 0; // SGI/PPI portion lives in redist
    const idx = widx - 1;
    if (idx >= SPI_BITMAP_WORDS) return 0;
    return words[idx];
}

const BitOp = enum { set, clear, replace };

fn writeSpiBitmap(words: []u32, byte_offset: u64, value: u64, op: BitOp) void {
    const widx = byte_offset >> 2;
    if (widx == 0) return;
    const idx = widx - 1;
    if (idx >= SPI_BITMAP_WORDS) return;
    const v: u32 = @intCast(value & 0xFFFFFFFF);
    switch (op) {
        .set => words[idx] |= v,
        .clear => words[idx] &= ~v,
        .replace => words[idx] = v,
    }
}

fn readSpiPriority(vgic: *const Vgic, byte_offset: u64) u64 {
    // Each priority is 1 byte; first 32 bytes cover SGI/PPI (RAZ here).
    if (byte_offset < 32) return 0;
    const spi = byte_offset - 32;
    if (spi >= MAX_SPIS) return 0;
    // 32-bit access reads four consecutive priority bytes.
    var out: u32 = 0;
    var i: u32 = 0;
    while (i < 4 and (spi + i) < MAX_SPIS) : (i += 1) {
        out |= @as(u32, vgic.spi_priority[spi + i]) << @as(u5, @intCast(i * 8));
    }
    return out;
}

fn writeSpiPriority(vgic: *Vgic, byte_offset: u64, value: u64) void {
    if (byte_offset < 32) return;
    const spi = byte_offset - 32;
    if (spi >= MAX_SPIS) return;
    var i: u32 = 0;
    while (i < 4 and (spi + i) < MAX_SPIS) : (i += 1) {
        vgic.spi_priority[spi + i] = @intCast((value >> @as(u6, @intCast(i * 8))) & 0xFF);
    }
}

/// GICD_ICFGR<n>: 2 bits per INTID, only bit[1] is meaningful (edge vs
/// level). The first two registers (n=0,1) cover SGIs/PPIs and are
/// RO/RAO/WI respectively per §12.9.12.
fn readSpiCfg(vgic: *const Vgic, byte_offset: u64) u64 {
    const widx: u32 = @intCast(byte_offset >> 2);
    if (widx < 2) return 0; // SGI: RAO; PPI: RAZ — caller hits RAZ here.
    const spi_word: u32 = widx - 2; // covers 16 SPIs each
    var out: u32 = 0;
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        const spi: u32 = spi_word * 16 + i;
        if (spi >= MAX_SPIS) break;
        if (bitTest(&vgic.spi_edge, spi)) {
            out |= @as(u32, 0b10) << @as(u5, @intCast(i * 2));
        }
    }
    return out;
}

fn writeSpiCfg(vgic: *Vgic, byte_offset: u64, value: u32) void {
    const widx: u32 = @intCast(byte_offset >> 2);
    if (widx < 2) return;
    const spi_word: u32 = widx - 2;
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        const spi: u32 = spi_word * 16 + i;
        if (spi >= MAX_SPIS) break;
        const cfg: u2 = @intCast((value >> @as(u5, @intCast(i * 2))) & 0b11);
        if ((cfg & 0b10) != 0) {
            bitSet(&vgic.spi_edge, spi);
        } else {
            bitClear(&vgic.spi_edge, spi);
        }
    }
}

/// GICD_IROUTER<n>: 64-bit per SPI starting at INTID 32. The first
/// 32 entries (INTIDs 0..31) are reserved per §12.9.13.
fn readSpiRouter(vgic: *const Vgic, byte_offset: u64) u64 {
    const idx = byte_offset >> 3;
    if (idx < 32) return 0;
    const spi = idx - 32;
    if (spi >= MAX_SPIS) return 0;
    return vgic.spi_router[spi];
}

fn writeSpiRouter(vgic: *Vgic, byte_offset: u64, value: u64) void {
    const idx = byte_offset >> 3;
    if (idx < 32) return;
    const spi = idx - 32;
    if (spi >= MAX_SPIS) return;
    vgic.spi_router[spi] = value;
}

// ===========================================================================
// Redistributor MMIO handlers
// ===========================================================================

/// GICv3 §12.10 redistributor read decode. The caller has already
/// adjusted `offset` to be relative to the start of this vCPU's GICR
/// frame pair (RD_base at offset 0; SGI_base at offset 0x10000).
fn redistRead(state: *VcpuState, vgic: *Vgic, offset: u64, size: u8) u64 {
    _ = size;
    const flags = state.lock.lockIrqSave();
    defer state.lock.unlockIrqRestore(flags);

    return switch (offset) {
        GICR_CTLR => state.gicr_ctlr,
        GICR_IIDR => GICD_IIDR_VALUE,
        // GICR_TYPER §12.10.27. Bits[63:32] = Affinity[3:0]; bits[31:24] =
        // Processor_Number; bit 4 = Last (set on the final redistributor
        // in the GICR address range).
        GICR_TYPER => blk: {
            var v: u64 = 0;
            v |= @as(u64, state.vcpu_index) << 8; // Processor_Number
            v |= @as(u64, state.vcpu_index) << 32; // Aff0
            if (state.vcpu_index == vgic.num_vcpus - 1) v |= 1 << 4; // Last
            break :blk v;
        },
        GICR_WAKER => state.gicr_waker,
        GICR_PIDR2 => PIDR2_GICV3,

        GICR_SGI_IGROUPR0 => state.sgi_ppi_group,
        GICR_SGI_ISENABLER0, GICR_SGI_ICENABLER0 => state.sgi_ppi_enabled,
        GICR_SGI_ISPENDR0, GICR_SGI_ICPENDR0 => state.sgi_ppi_pending,
        GICR_SGI_ISACTIVER0, GICR_SGI_ICACTIVER0 => state.sgi_ppi_active,
        GICR_SGI_IPRIORITYR_BASE...GICR_SGI_IPRIORITYR_END => readSgiPpiPriority(state, offset - GICR_SGI_IPRIORITYR_BASE),
        GICR_SGI_ICFGR0 => 0xAAAAAAAA, // SGIs are always edge per §9.4.12 (each pair = 0b10)
        GICR_SGI_ICFGR1 => blk: {
            var v: u32 = 0;
            var i: u32 = 0;
            while (i < 16) : (i += 1) {
                if ((state.sgi_ppi_edge & (@as(u32, 1) << @as(u5, @intCast(16 + i)))) != 0) {
                    v |= @as(u32, 0b10) << @as(u5, @intCast(i * 2));
                }
            }
            break :blk v;
        },
        else => 0,
    };
}

fn redistWrite(state: *VcpuState, vgic: *Vgic, offset: u64, size: u8, value: u64) void {
    _ = size;
    _ = vgic;
    const flags = state.lock.lockIrqSave();
    defer state.lock.unlockIrqRestore(flags);

    const v32: u32 = @intCast(value & 0xFFFFFFFF);
    switch (offset) {
        GICR_CTLR => state.gicr_ctlr = v32 & 0x1, // EnableLPIs ignored, bookkeeping only
        GICR_IIDR, GICR_TYPER, GICR_PIDR2 => {}, // RO
        GICR_WAKER => {
            // §12.10.21: clearing ProcessorSleep wakes the redistributor;
            // hardware then clears ChildrenAsleep. We do it synchronously.
            const ps = (v32 & GICR_WAKER_PROCESSOR_SLEEP) != 0;
            if (ps) {
                state.gicr_waker = GICR_WAKER_PROCESSOR_SLEEP | GICR_WAKER_CHILDREN_ASLEEP;
            } else {
                state.gicr_waker = 0;
            }
        },

        GICR_SGI_IGROUPR0 => state.sgi_ppi_group = v32,
        GICR_SGI_ISENABLER0 => state.sgi_ppi_enabled |= v32,
        GICR_SGI_ICENABLER0 => state.sgi_ppi_enabled &= ~v32,
        GICR_SGI_ISPENDR0 => state.sgi_ppi_pending |= v32,
        GICR_SGI_ICPENDR0 => state.sgi_ppi_pending &= ~v32,
        GICR_SGI_ISACTIVER0 => state.sgi_ppi_active |= v32,
        GICR_SGI_ICACTIVER0 => state.sgi_ppi_active &= ~v32,
        GICR_SGI_IPRIORITYR_BASE...GICR_SGI_IPRIORITYR_END => writeSgiPpiPriority(state, offset - GICR_SGI_IPRIORITYR_BASE, v32),
        GICR_SGI_ICFGR0 => {}, // SGIs always edge — RAO/WI per §9.4.12
        GICR_SGI_ICFGR1 => {
            var i: u32 = 0;
            while (i < 16) : (i += 1) {
                const cfg: u2 = @intCast((v32 >> @as(u5, @intCast(i * 2))) & 0b11);
                const bit: u5 = @intCast(16 + i);
                if ((cfg & 0b10) != 0) {
                    state.sgi_ppi_edge |= (@as(u32, 1) << bit);
                } else {
                    state.sgi_ppi_edge &= ~(@as(u32, 1) << bit);
                }
            }
        },
        else => {},
    }
}

fn readSgiPpiPriority(state: *const VcpuState, byte_offset: u64) u64 {
    if (byte_offset >= NUM_SGI_PPI) return 0;
    var out: u32 = 0;
    var i: u32 = 0;
    while (i < 4 and (byte_offset + i) < NUM_SGI_PPI) : (i += 1) {
        out |= @as(u32, state.sgi_ppi_priority[byte_offset + i]) << @as(u5, @intCast(i * 8));
    }
    return out;
}

fn writeSgiPpiPriority(state: *VcpuState, byte_offset: u64, value: u32) void {
    if (byte_offset >= NUM_SGI_PPI) return;
    var i: u32 = 0;
    while (i < 4 and (byte_offset + i) < NUM_SGI_PPI) : (i += 1) {
        state.sgi_ppi_priority[byte_offset + i] = @intCast((value >> @as(u5, @intCast(i * 8))) & 0xFF);
    }
}

// ===========================================================================
// Sysreg accessors for the virtual CPU interface
// ===========================================================================
//
// Direct EL1 `msr/mrs` on ICH_*_EL2 would trap as an undefined
// instruction (ARM ARM D13.8). The kernel therefore reaches the
// virtual CPU interface sysregs via the `hvc_vgic_{detect_lrs,
// prepare_entry,save_exit}` stubs in `arch/aarch64/vm.zig` which run
// at EL2 and index `VcpuHwShadow` by the pinned offsets asserted
// above. See `prepareEntry` / `saveExit` / `detectListRegs` for the
// call sites.

// ===========================================================================
// Cross-arch / cross-host build guard
// ===========================================================================
//
// All of the system register asm in this file uses S3_4_C12_C* opcodes
// which only assemble with the aarch64 backend. This file must therefore
// only be referenced from an aarch64 build; the kvm/kvm.zig index file
// does the gating.

comptime {
    _ = std;
}
