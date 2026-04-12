/// Intel VT-d (Virtualization Technology for Directed I/O) IOMMU driver.
///
/// Implements DMA remapping using legacy mode (root table + context table +
/// second-stage page tables) per the Intel VT-d Architecture Specification,
/// Rev 4.0, June 2022 (Order Number: D51397-015).
///
/// Translation flow (Section 3.4):
///   DMA request with BDF → Root Table[Bus] → Context Table[Dev:Fn]
///   → Second-Stage Page Tables (4-level, 48-bit) → Host Physical Address
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const MMIO_PERMS: MemoryPerms = .{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .not_cacheable,
    .global_perm = .not_global,
    .privilege_perm = .kernel,
};

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

/// Context Command Register (Section 11.4.6.1, offset 028h).
/// 64-bit register for context-cache invalidation commands.
const REG_CCMD = 0x28;

// ── Command/status bit definitions (Section 11.4.4) ─────────────────────

/// GCMD bit 31: Translation Enable — write 1 to enable DMA remapping.
const GCMD_TE: u32 = 1 << 31;

/// GCMD bit 30: Set Root Table Pointer — one-shot command to latch
/// the value in RTADDR_REG. Cleared automatically; do not preserve.
const GCMD_SRTP: u32 = 1 << 30;

/// GSTS bit 31: Translation Enable Status — set when TE is active.
const GSTS_TES: u32 = 1 << 31;

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

/// Legacy-mode Root Table Entry (Section 9.1, Table 3).
///
/// 128-bit entry, one per PCI bus (256 entries in root table).
/// The upper 64 bits are reserved in legacy mode (used only in
/// scalable mode for the upper context table pointer).
///
/// Layout:
///   Bits 127:64 — Reserved (must be 0)
///   Bits 63:12  — CTP: 4KB-aligned physical address of context table
///   Bits 11:1   — Reserved (must be 0)
///   Bit  0      — P: Present (1 = valid entry)
const RootEntry = packed struct(u128) {
    present: bool,
    _res0: u11 = 0,
    context_table_ptr: u52,
    _res1: u64 = 0,
};

/// Legacy-mode Context Table Entry (Section 9.3, Table 12).
///
/// 128-bit entry, 256 per context table (one per devfn on a PCI bus).
/// Maps a device to its second-stage page table and domain ID.
///
/// Layout:
///   Bits 127:88 — Reserved
///   Bits 87:72  — DID: 16-bit Domain Identifier
///   Bit  71     — Reserved
///   Bits 70:67  — Ignored
///   Bits 66:64  — AW: Address Width (001=39-bit/3-level, 010=48-bit/4-level, 011=57-bit/5-level)
///   Bits 63:12  — SLPTPTR: 4KB-aligned second-stage page table pointer
///   Bits 11:4   — Reserved
///   Bits 3:2    — TT: Translation Type (00=second-stage only, 10=pass-through)
///   Bit  1      — FPD: Fault Processing Disable (1=suppress fault logging)
///   Bit  0      — P: Present
const ContextEntry = packed struct(u128) {
    present: bool,
    fault_disable: bool,
    translation_type: u2,
    _res0: u8 = 0,
    slptptr: u52,
    address_width: u3,
    _ignored: u1 = 0,
    _avail: u3 = 0,
    _res1: u1 = 0,
    domain_id: u16,
    _res2: u40 = 0,
};

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
    const pmm_iface = pmm.global_pmm.?.allocator();
    const page = try pmm_iface.create(paging.PageMem(.page4k));
    @memset(std.mem.asBytes(page), 0);
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

    try arch.mapPage(memory_init.kernel_addr_space_root, reg_base_phys, reg_base_virt, MMIO_PERMS);
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

var translation_enabled: bool = false;

/// Enable DMA remapping by setting GCMD.TE (Section 11.4.4.1).
///
/// Called after all initial setupDevice() calls so context entries are
/// populated before translation is active. Per Section 6.5, software must
/// invalidate context cache and IOTLB before enabling translation to
/// ensure the IOMMU does not use stale cached entries from a prior
/// translation-enabled session.
///
/// After writing TE=1, polls GSTS.TES until hardware confirms translation
/// is active. Hardware enables remapping at a deterministic transaction
/// boundary so in-flight DMA is fully remapped or not at all.
pub fn enableTranslation() void {
    if (!initialized or translation_enabled) return;
    invalidateContextCache();
    invalidateIotlb();
    issueGlobalCommand(GCMD_TE, GSTS_TES);
    translation_enabled = true;
}

/// Configure a PCI device for DMA remapping through the IOMMU.
///
/// Populates the root table entry for the device's bus (if not already
/// present) and the context table entry for its dev:fn. Each device gets
/// its own second-stage page table (4-level, 48-bit) and a unique domain ID.
///
/// Root table (Section 9.1): 256 entries indexed by PCI bus number.
/// Each entry points to a 4KB context table.
///
/// Context table (Section 9.3): 256 entries indexed by devfn
/// (device[4:0] << 3 | function[2:0]). Each entry contains:
///   - SLPTPTR: second-stage page table root (4KB-aligned physical address)
///   - AW = 010b: 48-bit AGAW / 4-level page table (Section 9.3, Table 12)
///   - TT = 00b: untranslated requests only, second-stage translation
///   - DID: domain identifier, set to bus:devfn for uniqueness
///
/// After populating a new context entry, global context cache and IOTLB
/// invalidation are performed (Section 6.5) so the IOMMU re-walks the
/// root/context tables on next DMA from this device.
pub fn setupDevice(device: *DeviceRegion) !void {
    if (!initialized) return;

    const root_entries: *[256]RootEntry = @ptrFromInt(root_table_virt.addr);
    const pci = &device.detail.pci;
    const bus = pci.bus;

    if (!root_entries[bus].present) {
        const ctx = try allocZeroedPage();
        root_entries[bus] = .{
            .present = true,
            .context_table_ptr = @truncate(ctx.phys.addr >> 12),
        };
    }

    const ctx_phys = PAddr.fromInt(@as(u64, root_entries[bus].context_table_ptr) << 12);
    const ctx_virt = VAddr.fromPAddr(ctx_phys, null);
    const ctx_entries: *[256]ContextEntry = @ptrFromInt(ctx_virt.addr);
    // Context index = dev[4:0] << 3 | func[2:0], matching PCI devfn encoding
    const ctx_idx = @as(u8, pci.dev) * 8 + pci.func;

    if (!ctx_entries[ctx_idx].present) {
        const pt = try allocZeroedPage();
        pci.dma_page_table_root = pt.phys;
        ctx_entries[ctx_idx] = .{
            .present = true,
            .fault_disable = false,
            // TT = 00b: untranslated requests, second-stage translation (Section 9.3)
            .translation_type = 0,
            // AW = 010b: 48-bit AGAW, 4-level page table (Section 9.3, CAP.SAGAW bit 2)
            .address_width = 2,
            .slptptr = @truncate(pt.phys.addr >> 12),
            // Domain ID: unique per device, using bus:devfn encoding
            .domain_id = @as(u16, pci.bus) << 8 | @as(u16, ctx_idx),
        };

        // Invalidate caches so the IOMMU picks up the new context entry.
        // Per Section 6.5, context-cache invalidation must precede IOTLB
        // invalidation because context-cache info may tag IOTLB entries.
        invalidateContextCache();
        invalidateIotlb();
    }
}

/// Map a single 4KB DMA page in a device's second-stage page table.
///
/// Walks/allocates a 4-level page table hierarchy (PML4 → PDPT → PD → PT)
/// per Section 9.8-9.9. Each level is a 4KB page containing 512 64-bit entries.
///
/// Index extraction from the 48-bit DMA address:
///   PML4 index = bits 47:39 (Section 9.9, Table 24)
///   PDPT index = bits 38:30
///   PD index   = bits 29:21
///   PT index   = bits 20:12
///
/// Intermediate entries (PML4E, PDPTE, PDE referencing next level):
///   Bit 0 = R (Read), Bit 1 = W (Write) — set to 1 for present entries.
///   Bits (HAW-1):12 = physical address of next-level table.
///   Per Tables 24, 40, 42: R and W act as aggregate permissions.
///
/// Leaf PTE (Section 9.9, Table 43):
///   Bit 0 = R, Bit 1 = W — set to grant read+write DMA access.
///   Bits (HAW-1):12 = host physical address of the 4KB page.
///   Bits 5:3 (EMT), bit 6 (IPAT), bit 11 (SNP) are 0 (defaults for
///   legacy mode where these fields are ignored or reserved).
pub fn mapDmaPage(device: *DeviceRegion, dma_addr: u64, phys: PAddr) !void {
    if (!initialized or device.detail.pci.dma_page_table_root.addr == 0) return error.NotSetup;

    const pml4_virt = VAddr.fromPAddr(device.detail.pci.dma_page_table_root, null);
    const pml4: *[512]u64 = @ptrFromInt(pml4_virt.addr);

    const pml4_idx: u9 = @truncate((dma_addr >> 39) & 0x1FF);
    const pdpt_idx: u9 = @truncate((dma_addr >> 30) & 0x1FF);
    const pd_idx: u9 = @truncate((dma_addr >> 21) & 0x1FF);
    const pt_idx: u9 = @truncate((dma_addr >> 12) & 0x1FF);

    // PML4E → PDPT (Table 24): R=1, W=1 (bits 1:0 = 0x3)
    if (pml4[pml4_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pml4[pml4_idx] = page.phys.addr | 0x3;
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);

    // PDPTE → PD (Table 40): R=1, W=1
    if (pdpt[pdpt_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pdpt[pdpt_idx] = page.phys.addr | 0x3;
    }
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);

    // PDE → PT (Table 42): R=1, W=1
    if (pd[pd_idx] & 1 == 0) {
        const page = try allocZeroedPage();
        pd[pd_idx] = page.phys.addr | 0x3;
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0xFFFFFFFFF000), null).addr);

    // Leaf PTE (Table 43): R=1, W=1, address in bits (HAW-1):12
    pt[pt_idx] = phys.addr | 0x3;
}

/// Remove a 4KB DMA page mapping from a device's second-stage page table.
///
/// Walks the 4-level page table to find the leaf PTE and clears it (R=0, W=0
/// makes the entry not-present). Performs a global IOTLB invalidation after
/// clearing to ensure the IOMMU does not use a stale cached translation
/// (Section 6.1: when CM=0, present→not-present transitions require
/// invalidation before the change is guaranteed visible to hardware).
pub fn unmapDmaPage(device: *DeviceRegion, dma_addr: u64) void {
    if (!initialized or device.detail.pci.dma_page_table_root.addr == 0) return;

    const pml4_virt = VAddr.fromPAddr(device.detail.pci.dma_page_table_root, null);
    const pml4: *[512]u64 = @ptrFromInt(pml4_virt.addr);
    const pml4_idx: u9 = @truncate((dma_addr >> 39) & 0x1FF);
    if (pml4[pml4_idx] & 1 == 0) return;

    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0xFFFFFFFFF000), null).addr);
    const pdpt_idx: u9 = @truncate((dma_addr >> 30) & 0x1FF);
    if (pdpt[pdpt_idx] & 1 == 0) return;

    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0xFFFFFFFFF000), null).addr);
    const pd_idx: u9 = @truncate((dma_addr >> 21) & 0x1FF);
    if (pd[pd_idx] & 1 == 0) return;

    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0xFFFFFFFFF000), null).addr);
    const pt_idx: u9 = @truncate((dma_addr >> 12) & 0x1FF);
    pt[pt_idx] = 0;

    invalidateIotlb();
}

/// Perform a global context-cache invalidation (Section 11.4.6.1).
///
/// Writes to CCMD_REG (offset 028h) with:
///   Bit 63 = ICC (Invalidate Context-Cache): set to initiate invalidation.
///   Bits 62:61 = CIRG = 01b (Global Invalidation Request).
///
/// Polls ICC (bit 63) until hardware clears it, indicating completion.
/// Hardware may perform invalidation at a coarser granularity and reports
/// the actual granularity in CAIG (bits 60:59).
///
/// Per Section 11.4.6.1: "Since information from the context-cache may be
/// used by hardware to tag IOTLB entries, software must perform domain-
/// selective (or global) invalidation of IOTLB after the context-cache
/// invalidation has completed."
fn invalidateContextCache() void {
    // ICC=1 (bit 63), CIRG=01 (bit 61) = global invalidation
    writeReg64(REG_CCMD, (@as(u64, 1) << 63) | (@as(u64, 1) << 61));
    var timeout: u32 = 0;
    while (timeout < 1000000) {
        const val = @as(*const volatile u64, @ptrFromInt(iommu_base + REG_CCMD)).*;
        if (val & (@as(u64, 1) << 63) == 0) break;
        timeout += 1;
    }
}

/// Perform a global IOTLB invalidation (Section 11.4.6.3).
///
/// The IOTLB Invalidate Register is at offset IRO+8 (Section 11.4.6.2),
/// where IRO is read from ECAP.IRO during init(). Writes with:
///   Bit 63 = IVT (Invalidate IOTLB): set to initiate invalidation.
///   Bits 61:60 = IIRG = 01b (Global Invalidation Request).
///   Bit 62 is reserved and must be 0.
///
/// Polls IVT (bit 63) until hardware clears it, indicating completion.
/// Hardware reports actual granularity in IAIG (bits 58:57).
///
/// Must be called after context-cache invalidation (Section 11.4.6.1)
/// and after modifying page table entries (Section 6.1, 6.5).
pub fn invalidateIotlb() void {
    // IOTLB_REG is at IRO + 8 (Section 11.4.6.2)
    const reg = iotlb_offset + 8;
    // IVT=1 (bit 63), IIRG=01 (bit 60) = global invalidation
    writeReg64(reg, @as(u64, 1) << 63 | @as(u64, 1) << 60);
    var timeout: u32 = 0;
    while (timeout < 1000000) {
        const val = @as(*const volatile u64, @ptrFromInt(iommu_base + reg)).*;
        if (val & (@as(u64, 1) << 63) == 0) break;
        timeout += 1;
    }
}
