/// Intel VT-d (Virtualization Technology for Directed I/O) IOMMU driver.
///
/// Implements DMA remapping using legacy mode (root table + context table +
/// second-stage page tables) per the Intel VT-d Architecture Specification,
/// Rev 4.0, June 2022 (Order Number: D51397-015).
///
/// Translation flow (Section 3.4):
///   DMA request with BDF → Root Table[Bus] → Context Table[Dev:Fn]
///   → Second-Stage Page Tables (4-level, 48-bit) → Host Physical Address
const zag = @import("zag");

const arch_paging = zag.arch.x64.paging;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const MMIO_PERMS: MemoryPerms = .{ .read = true, .write = true };

// ── Register offsets (Section 11.4, Table 1) ────────────────────────────

/// Extended Capability Register (Section 11.4.3, offset 010h).
/// Reports extended hardware capabilities. We read the IRO field
/// (bits 17:8) to locate the IOTLB registers.
const REG_ECAP = 0x10;

/// Global Command Register (Section 11.4.4.1, offset 018h).
/// **Write-only.** Controls translation enable, root table pointer
/// latching, write buffer flush, and other global commands.
/// Reading this register returns undefined values — software must
/// read GSTS to determine current state.
const REG_GCMD = 0x18;

/// Global Status Register (Section 11.4.4.2, offset 01Ch).
/// **Read-only.** Reports the status of commands issued via GCMD.
/// Bit positions mirror GCMD (e.g. bit 31 = TES mirrors TE).
const REG_GSTS = 0x1C;

/// Root Table Address Register (Section 11.4.5, offset 020h).
/// Bits 63:12 = 4KB-aligned root table physical address.
/// Bits 11:10 = TTM (Translation Table Mode): 00=legacy, 01=scalable.
/// Takes effect only after SRTP command via GCMD.
const REG_RTADDR = 0x20;

// ── Command/status bit definitions (Section 11.4.4) ─────────────────────

/// GCMD bit 30: Set Root Table Pointer — one-shot command to latch
/// the value in RTADDR_REG. Cleared automatically; do not preserve.
const GCMD_SRTP: u32 = 1 << 30;

/// GSTS bit 30: Root Table Pointer Status — set when SRTP completes.
const GSTS_RTPS: u32 = 1 << 30;

/// Mask to extract persistent command state from GSTS for GCMD writes.
/// Per Section 11.4.4.1, when writing GCMD software must:
///   1. Read GSTS_REG
///   2. AND with 0x96FFFFFF to clear one-shot bits (SRTP[30], WBF[27],
///      SIRTP[24], CFI[23]) and reserved bits [29:28]
///   3. OR in the desired command bit
///   4. Write to GCMD_REG
/// This preserves persistent enables (TE[31], QIE[26], IRE[25]) while
/// clearing one-shot command bits that must not be re-asserted.
const GSTS_CMD_MASK: u32 = 0x96FFFFFF;

/// Offset of the IOTLB registers, derived from ECAP.IRO at init time.
/// The IOTLB Invalidate Register is at this offset + 8 (Section 11.4.6.2).
var iotlb_offset: u32 = 0;

var iommu_base: u64 = 0;
var root_table_phys: PAddr = PAddr.fromInt(0);
var root_table_virt: VAddr = VAddr.fromInt(0);
var initialized: bool = false;

/// Read a 32-bit MMIO register at the given offset from the IOMMU base.
/// Per Section 11.2, software accesses 32-bit registers as aligned doublewords.
fn readReg32(offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(iommu_base + offset);
    return ptr.*;
}

/// Write a 32-bit MMIO register at the given offset from the IOMMU base.
fn writeReg32(offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(iommu_base + offset);
    ptr.* = value;
}

/// Write a 64-bit MMIO register at the given offset from the IOMMU base.
/// Per Section 11.2, hardware completes quadword writes in order
/// (lower doubleword first, upper doubleword second).
fn writeReg64(offset: u32, value: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(iommu_base + offset);
    ptr.* = value;
}

/// Allocate a zeroed 4KB page and return both its physical and virtual addresses.
/// Used for root tables, context tables, and page table levels — all of which
/// must be 4KB-aligned and zero-initialized (Section 9.1, 9.3, 9.8).
fn allocZeroedPage() !struct { phys: PAddr, virt: VAddr } {
    const pmm_mgr = &pmm.global_pmm.?;
    const page = try pmm_mgr.create(paging.PageMem(.page4k));
    const virt = VAddr.fromInt(@intFromPtr(page));
    const phys = PAddr.fromVAddr(virt, null);
    return .{ .phys = phys, .virt = virt };
}

/// Read current persistent GCMD state from GSTS and issue a command.
///
/// GCMD_REG is write-only (Section 11.4.4.1) — reads return undefined.
/// The spec prescribes this sequence for issuing commands:
///   1. Read GSTS_REG to get current state
///   2. Mask with 0x96FFFFFF to clear one-shot bits (SRTP, WBF, SIRTP, CFI)
///   3. OR in the desired command bit
///   4. Write to GCMD_REG
///   5. Poll GSTS_REG until the corresponding status bit confirms completion
fn issueGlobalCommand(cmd_bit: u32, status_bit: u32) void {
    const current = readReg32(REG_GSTS) & GSTS_CMD_MASK;
    writeReg32(REG_GCMD, current | cmd_bit);
    var timeout: u32 = 0;
    while (timeout < 1000000) {
        if (readReg32(REG_GSTS) & status_bit != 0) break;
        timeout += 1;
    }
}

/// Initialize the Intel VT-d remapping hardware unit.
///
/// Performs the following sequence per the spec:
///   1. Map the MMIO register page (implementation-specific base from ACPI DMAR)
///   2. Read ECAP.IRO (Section 11.4.3, bits 17:8) to locate IOTLB registers.
///      IRO is a 10-bit field giving the offset in 16-byte units.
///   3. Allocate and zero a 4KB root table (256 RootEntry, Section 9.1)
///   4. Write root table address to RTADDR_REG (Section 11.4.5).
///      Bits 63:12 = physical address, bits 11:10 = TTM = 00 (legacy mode).
///      Since the page is 4KB-aligned, bits 11:0 are 0, giving TTM=00.
///   5. Issue SRTP command (Section 11.4.4.1) to latch the root table pointer.
///      Hardware sets GSTS.RTPS when complete.
///
/// Translation enable (TE) is deferred to enableTranslation() so that
/// setupDevice() can populate context entries first — if TE were set now,
/// the IOMMU would cache "not present" entries (Section 6.1, CM=0 still
/// caches present/absent distinction for root and context entries).
pub fn init(reg_base_phys: PAddr) !void {
    const reg_base_virt = VAddr.fromPAddr(reg_base_phys, null);

    try arch_paging.mapPage(memory_init.kernel_addr_space_root, reg_base_phys, reg_base_virt, MMIO_PERMS, .kernel_mmio);
    iommu_base = reg_base_virt.addr;

    // ECAP.IRO (Section 11.4.3): bits 17:8 give the IOTLB register offset
    // in 16-byte (paragraph) units. Shift left by 4 to get byte offset.
    const ecap: u64 = @as(*const volatile u64, @ptrFromInt(iommu_base + REG_ECAP)).*;
    iotlb_offset = @truncate(((ecap >> 8) & 0x3FF) << 4);

    const root = try allocZeroedPage();
    root_table_phys = root.phys;
    root_table_virt = root.virt;

    // RTADDR_REG (Section 11.4.5): bits 63:12 = root table address.
    // Bits 11:10 = TTM = 00 (legacy mode). Page-aligned address ensures TTM=00.
    writeReg64(REG_RTADDR, root_table_phys.addr);

    // Issue SRTP command and wait for GSTS.RTPS (Section 11.4.4.1).
    issueGlobalCommand(GCMD_SRTP, GSTS_RTPS);

    initialized = true;
}

