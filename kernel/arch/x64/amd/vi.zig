/// AMD I/O Virtualization Technology (AMD-Vi / IOMMU) driver.
///
/// Implements host-level DMA address translation per the AMD IOMMU specification
/// (AMD Publication #48882, Rev 3.05, January 2020). This driver programs the
/// IOMMU to enforce per-device I/O page tables so that each device can only DMA
/// to explicitly mapped physical pages.
///
/// Key spec references used throughout:
///   - Section 2.2.2: Device Table Entry (DTE) format (Figure 7, Table 7)
///   - Section 2.2.3: I/O Page Tables for Host Translations (Table 15, Figures 8-10)
///   - Section 2.3:   Starting the IOMMU / Data Structure Initialization
///   - Section 2.4:   Commands (generic format in Figure 40)
///   - Section 3.3.1: MMIO Control and Status Registers
///   - Section 3.3.13: Command and Event Log Pointer Registers
const zag = @import("zag");

const arch_paging = zag.arch.x64.paging;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const MMIO_PERMS: MemoryPerms = .{ .read = true, .write = true };

// ---------------------------------------------------------------------------
// MMIO register offsets (spec Section 3.3.1, Section 3.3.13)
// ---------------------------------------------------------------------------

/// Device Table Base Address Register — spec MMIO Offset 0000h.
/// Bits [51:12] = DevTabBase, [8:0] = Size (n → (n+1)*4KB).
const MMIO_DEV_TABLE_BASE = 0x0000;

/// Command Buffer Base Address Register — spec MMIO Offset 0008h.
/// Bits [59:56] = ComLen (power-of-2), [51:12] = ComBase.
const MMIO_CMD_BUF_BASE = 0x0008;

/// Event Log Base Address Register — spec MMIO Offset 0010h.
/// Bits [59:56] = EventLen (power-of-2), [51:12] = EventBase.
const MMIO_EVT_LOG_BASE = 0x0010;

/// IOMMU Control Register — spec MMIO Offset 0018h.
/// Controls IOMMU enable, command buffer enable, event log enable, etc.
const MMIO_CONTROL = 0x0018;

// ---------------------------------------------------------------------------
// IOMMU Control Register bit definitions (spec MMIO Offset 0018h)
// ---------------------------------------------------------------------------

/// EventLogEn (bit 2): Enable event logging to the Event Log buffer.
const CTRL_EVT_LOG_EN: u64 = 1 << 2;

/// CmdBufEn (bit 12): Start/restart command buffer processing.
const CTRL_CMD_BUF_EN: u64 = 1 << 12;

/// Coherent (bit 10): Device Table reads are snooped by the processor.
/// When set, IOMMU page table walks use coherent (snooped) accesses,
/// so software doesn't need explicit cache flushes after page table updates.
const CTRL_COHERENT_EN: u64 = 1 << 10;

// ---------------------------------------------------------------------------
// I/O Page Table Entry (PTE/PDE) bit definitions (spec Section 2.2.3, Figures 8-10)
// ---------------------------------------------------------------------------

/// IR (bit 61): I/O read permission. Set in both DTEs and page table entries.
/// Effective read permission is the AND of IR across the DTE and all walked entries.
const AMDVI_IR: u64 = 1 << 61;

/// IW (bit 62): I/O write permission. Set in both DTEs and page table entries.
/// Effective write permission is the AND of IW across the DTE and all walked entries.
const AMDVI_IW: u64 = 1 << 62;

/// Combined read+write permission bits for convenience.
const AMDVI_RW: u64 = AMDVI_IR | AMDVI_IW;

/// Mask for the page-aligned physical address field in page table entries.
/// Bits [51:12] hold the system physical address; bits [63:52] and [11:0] are
/// control/attribute fields (spec Table 17, Table 18).
const AMDVI_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// Command opcodes (spec Section 2.4, Figure 40)
//
// All IOMMU commands are 128 bits. The generic format places the 4-bit opcode
// at bits [31:28] of the +04 dword, which corresponds to bits [63:60] of the
// first 64-bit word when stored little-endian in memory.
// ---------------------------------------------------------------------------

/// COMPLETION_WAIT — spec Section 2.4.1, opcode 01h.
const CMD_COMPLETION_WAIT: u64 = @as(u64, 0x01) << 60;

/// INVALIDATE_DEVTAB_ENTRY — spec Section 2.4.2, opcode 02h.
const CMD_INVALIDATE_DEVTAB_ENTRY: u64 = @as(u64, 0x02) << 60;

/// INVALIDATE_IOMMU_PAGES — spec Section 2.4.3, opcode 03h.
const CMD_INVALIDATE_IOMMU_PAGES: u64 = @as(u64, 0x03) << 60;

const MAX_IOMMU_UNITS = 4;
const MAX_ALIASES = 128;

const IommuUnit = struct {
    base: u64 = 0,
    dev_table_phys: PAddr = PAddr.fromInt(0),
    dev_table_virt: VAddr = VAddr.fromInt(0),
    dev_table_size: u64 = 0,
    cmd_buf_phys: PAddr = PAddr.fromInt(0),
    cmd_buf_virt: VAddr = VAddr.fromInt(0),
    /// Command buffer length in bytes (minimum 4KB = 256 entries of 16 bytes).
    cmd_buf_len: u64 = 0,
    active: bool = false,

    /// Read a 64-bit MMIO register at the given offset from the unit's base.
    fn readReg64(self: *const IommuUnit, offset: u32) u64 {
        const ptr: *const volatile u64 = @ptrFromInt(self.base + offset);
        return ptr.*;
    }

    /// Write a 64-bit MMIO register at the given offset from the unit's base.
    fn writeReg64(self: *const IommuUnit, offset: u32, value: u64) void {
        const ptr: *volatile u64 = @ptrFromInt(self.base + offset);
        ptr.* = value;
    }
};

const AliasEntry = struct {
    source: u16 = 0,
    alias: u16 = 0,
};

var units: [MAX_IOMMU_UNITS]IommuUnit = .{IommuUnit{}} ** MAX_IOMMU_UNITS;
var unit_count: u32 = 0;
var aliases: [MAX_ALIASES]AliasEntry = .{AliasEntry{}} ** MAX_ALIASES;
var alias_count: u32 = 0;

fn allocZeroedPage() !struct { phys: PAddr, virt: VAddr } {
    const pmm_mgr = &pmm.global_pmm.?;
    const page = try pmm_mgr.create(paging.PageMem(.page4k));
    const virt = VAddr.fromInt(@intFromPtr(page));
    const phys = PAddr.fromVAddr(virt, null);
    return .{ .phys = phys, .virt = virt };
}

/// Register an alias mapping from IVRS device entries.
/// When the IOMMU sees DMA from `source`, it uses `alias` to index the Device Table.
pub fn addAlias(source: u16, alias: u16) void {
    if (alias_count < MAX_ALIASES) {
        aliases[alias_count] = .{ .source = source, .alias = alias };
        alias_count += 1;
    }
}

/// Initialize one IOMMU unit given its MMIO register base physical address.
///
/// This follows the startup sequence from spec Section 2.3.1:
///   1. Allocate and zero the Device Table; program MMIO Offset 0000h.
///   2. Allocate and zero the Command Buffer; program MMIO Offset 0008h.
///   3. Allocate and zero the Event Log; program MMIO Offset 0010h.
///   4. Initialize head/tail pointers to 0 (reset default).
///   5. Enable the IOMMU via the Control Register (MMIO Offset 0018h).
pub fn init(reg_base_phys: PAddr) !void {
    if (unit_count >= MAX_IOMMU_UNITS) return;

    var unit = &units[unit_count];

    // Map the IOMMU's MMIO register space (16KB = 4 pages) into kernel VA space.
    // The register space extends from the base through at least offset 0x2048
    // (command/event pointer registers), so 4 pages covers it.
    const num_mmio_pages: u32 = 4;
    var i: u32 = 0;
    while (i < num_mmio_pages) {
        const page_phys = PAddr.fromInt(reg_base_phys.addr + @as(u64, i) * paging.PAGE4K);
        const page_virt = VAddr.fromPAddr(page_phys, null);
        arch_paging.mapPage(memory_init.kernel_addr_space_root, page_phys, page_virt, MMIO_PERMS, .kernel_mmio) catch {
            i += 1;
            continue;
        };
        i += 1;
    }
    unit.base = VAddr.fromPAddr(reg_base_phys, null).addr;

    // -----------------------------------------------------------------------
    // Device Table: 65536 entries × 32 bytes = 2MB (512 pages).
    //
    // Spec Section 2.2.2: The Device Table is an array of 256-bit (32-byte)
    // entries indexed by the 16-bit DeviceID. Must be 4KB-aligned and a
    // multiple of 4KB in size.
    // -----------------------------------------------------------------------
    const dt_pages: u32 = 512;
    const dt_size = @as(u64, dt_pages) * paging.PAGE4K;
    const pmm_mgr = &pmm.global_pmm.?;
    const dt_mem = pmm_mgr.allocBlock(dt_size) orelse return error.OutOfMemory;

    // Initialize all DTEs to block DMA by default.
    //
    // Spec Table 8, V=1/TV=1/GV=0: "All fields in bits [127:2] are valid and
    // GPA-to-SPA translation is active." With Mode=000b, translation is
    // disabled and access is controlled by IR and IW (spec Table 7, Mode field).
    // Since IR=0 and IW=0, all device-initiated DMA reads and writes are
    // target-aborted by the IOMMU.
    {
        var dte_idx: u64 = 0;
        while (dte_idx < 65536) {
            const dte: *volatile u64 = @ptrFromInt(@intFromPtr(dt_mem) + dte_idx * 32);
            // V=1 (bit 0), TV=1 (bit 1) — blocks all DMA with IR=0, IW=0.
            dte.* = 0x3;
            dte_idx += 1;
        }
    }
    const dt_virt = VAddr.fromInt(@intFromPtr(dt_mem));
    unit.dev_table_phys = PAddr.fromVAddr(dt_virt, null);
    unit.dev_table_virt = dt_virt;
    unit.dev_table_size = dt_size;

    // Program the Device Table Base Address Register (MMIO Offset 0000h).
    //
    // Spec Section 3.3.1, MMIO Offset 0000h:
    //   Bits [51:12] = DevTabBase (4KB-aligned physical address)
    //   Bits [8:0]   = Size: unsigned n where table size = (n + 1) * 4KB
    //
    // For the full 2MB table: n = (2MB / 4KB) - 1 = 511 = 0x1FF.
    const dt_size_field: u64 = (dt_size / paging.PAGE4K) - 1;
    unit.writeReg64(MMIO_DEV_TABLE_BASE, unit.dev_table_phys.addr | (dt_size_field & 0x1FF));

    // -----------------------------------------------------------------------
    // Command Buffer: 4KB = 256 entries of 16 bytes each.
    //
    // Spec Section 3.3.1, MMIO Offset 0008h:
    //   Bits [59:56] = ComLen: power-of-2 length (min 1000b = 256 entries = 4KB)
    //   Bits [51:12] = ComBase: 4KB-aligned physical address
    //   Bits [11:0]  = Reserved
    //
    // ComLen = 8 (1000b) → 2^8 = 256 entries → 256 * 16 = 4096 bytes.
    // -----------------------------------------------------------------------
    const cmd = try allocZeroedPage();
    unit.cmd_buf_phys = cmd.phys;
    unit.cmd_buf_virt = cmd.virt;
    unit.cmd_buf_len = paging.PAGE4K;
    const cmd_len_bits: u64 = 8;
    unit.writeReg64(MMIO_CMD_BUF_BASE, unit.cmd_buf_phys.addr | (cmd_len_bits << 56));

    // -----------------------------------------------------------------------
    // Event Log: 4KB = 256 entries of 16 bytes each.
    //
    // Spec Section 3.3.1, MMIO Offset 0010h: same layout as Command Buffer.
    // EventLen = 8 → 256 entries (4KB).
    // -----------------------------------------------------------------------
    const evt = try allocZeroedPage();
    const evt_len_bits: u64 = 8;
    unit.writeReg64(MMIO_EVT_LOG_BASE, evt.phys.addr | (evt_len_bits << 56));

    // -----------------------------------------------------------------------
    // Prepare the IOMMU Control Register (MMIO Offset 0018h).
    //
    // Enable the command buffer, event log, and coherent mode now so that
    // setupDevice() can issue invalidation commands. IommuEn is deferred
    // to enableTranslation() — enabling now with empty page tables would
    // fault any early device DMA (same deferral strategy as Intel VT-d).
    //
    // Spec Section 3.3.1, MMIO Offset 0018h:
    //   Bit  0: IommuEn    — master enable (deferred)
    //   Bit  2: EventLogEn — events written to the Event Log
    //   Bit 10: Coherent   — DTE reads are snooped (coherent with CPU caches)
    //   Bit 12: CmdBufEn   — start fetching commands from the command buffer
    // -----------------------------------------------------------------------
    var ctrl = unit.readReg64(MMIO_CONTROL);
    ctrl |= CTRL_CMD_BUF_EN | CTRL_EVT_LOG_EN | CTRL_COHERENT_EN;
    unit.writeReg64(MMIO_CONTROL, ctrl);

    unit.active = true;
    unit_count += 1;
}



