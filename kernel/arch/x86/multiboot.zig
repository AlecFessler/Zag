//! Multiboot v1 definitions and utilities for `x86_64` kernels.
//!
//! Implements data structures and parsing routines for reading bootloader-provided
//! metadata according to the Multiboot Specification v1. This includes module parsing,
//! memory map enumeration, and flag validation for early-stage kernel initialization.
//!
//! Used by the kernel to interpret memory layout and modules passed by GRUB or other
//! Multiboot-compliant bootloaders.

const paging = @import("paging.zig");
const std = @import("std");

const PAddr = paging.PAddr;
const VAddr = paging.VAddr;

/// Classifies a physical memory region reported by the bootloader.
///
/// Values correspond to the Multiboot `type` field (minus 1 to start at 0).
/// Used to determine which areas of RAM are usable or reserved by firmware.
pub const MemoryRegionType = enum(u32) {
    /// Usable RAM available for general allocation.
    Available,

    /// Reserved memory that must not be overwritten.
    Reserved,

    /// ACPI-reclaimable memory, usable after ACPI tables are parsed.
    AcpiReclaimable,

    /// ACPI non-volatile memory, preserved across sleep states.
    AcpiNvs,

    /// Faulty or invalid memory, never used.
    BadMem,

    /// Converts a region type to a human-readable string.
    ///
    /// Returns:
    /// - String name for this region type.
    pub fn toString(self: @This()) []const u8 {
        return switch (self) {
            .Available => "Available",
            .Reserved => "Reserved",
            .AcpiReclaimable => "ACPI Reclaimable",
            .AcpiNvs => "ACPI non-volatile sleep memory",
            .BadMem => "Bad Memory",
        };
    }
};

/// Multiboot information structure provided at kernel entry.
///
/// Populated by the bootloader and referenced via the pointer passed to `kmain`.
/// Fields are conditionally valid based on `flags`. Contains module lists, memory
/// maps, and VBE/BIOS configuration data.
pub const MultibootInfo = packed struct {
    flags: u32,
    mem_lower: u32,
    mem_upper: u32,
    boot_dev: u32,
    cmdline: u32,
    mods_count: u32,
    mods_addr: u32,
    elf_sections: ElfSectionHeaderTable,
    mmap_len: u32,
    mmap_addr: u32,
    drives_len: u32,
    drives_addr: u32,
    config_table: u32,
    boot_loader: u32,
    apm_table: u32,
    vbe_ctl_info: u32,
    vbe_mode_info: u32,
    vbe_mode: u16,
    vbe_interface_seg: u16,
    vbe_interface_off: u16,
    vbe_interface_len: u16,
};

/// Physical memory region entry derived from the bootloader’s memory map.
pub const MemoryRegion = struct {
    addr: u64,
    len: u64,
    region_type: MemoryRegionType,
};

/// Describes a loaded module passed by the bootloader (e.g., initrd or symbol map).
pub const Mod = packed struct {
    start: u32,
    end: u32,
    cmdline: u32,
    padding: u32,
};

/// Single Multiboot memory map entry (unaligned, bootloader-provided).
pub const MultibootMmapEntry = packed struct {
    size: u32,
    addr: u64,
    len: u64,
    /// Region type (1 = usable, >1 = reserved or special).
    type: u32,
};

/// ELF section header table metadata passed by the bootloader.
pub const ElfSectionHeaderTable = packed struct {
    num: u32,
    size: u32,
    addr: u32,
    shndx: u32,
};

/// Magic constant confirming a valid Multiboot-compliant boot.
pub const MAGIC = 0x2BADB002;

/// Maximum number of memory regions we store from the bootloader map.
pub const MAX_REGIONS = 32;

/// Returns true if a given `bit` in `flags` is set.
///
/// Arguments:
/// - `flags`: bitfield to test.
/// - `bit`: bit index (0-based).
///
/// Returns:
/// - `true` if `flags` has `bit` set; otherwise `false`.
pub fn checkFlag(flags: u32, bit: u5) bool {
    return 1 == (1 & (flags >> bit));
}

/// Parses the Multiboot memory map into a slice of `MemoryRegion`s.
///
/// Arguments:
/// - `info`: pointer to the `MultibootInfo`.
/// - `regions`: preallocated buffer (length `MAX_REGIONS`) to fill.
///
/// Returns:
/// - Slice of populated `MemoryRegion` entries within `regions`.
pub fn parseMemoryMap(info: *const MultibootInfo, regions: *[MAX_REGIONS]MemoryRegion) []MemoryRegion {
    const mmap_paddr = PAddr.fromInt(info.mmap_addr);
    var mmap_vaddr = VAddr.fromPAddr(mmap_paddr, .kernel);
    const mmap_end_vaddr = VAddr.fromInt(mmap_vaddr.addr + info.mmap_len);
    var i: u64 = 0;

    while (mmap_vaddr.addr < mmap_end_vaddr.addr) : (i += 1) {
        const entry = mmap_vaddr.getPtr(*align(1) const MultibootMmapEntry);
        regions[i] = .{
            .addr = entry.addr,
            .len = entry.len,
            .region_type = @enumFromInt(entry.type - 1),
        };
        mmap_vaddr.addr += entry.size + @sizeOf(u32);
    }

    return regions[0..i];
}

/// Parses bootloader modules to find one matching `wanted`, or a heuristic fallback.
///
/// Attempts to locate a module by its name (as provided in GRUB’s `module` line),
/// or by detecting a file that resembles a symbol map.
///
/// Arguments:
/// - `info`: pointer to the `MultibootInfo`.
/// - `wanted`: module name to match (full or suffix).
///
/// Returns:
/// - Byte slice of the chosen module in kernel virtual address space, or `null` if not found.
pub fn parseModules(info: *const MultibootInfo, wanted: []const u8) ?[]const u8 {
    if (!checkFlag(info.flags, 3) or info.mods_count == 0) return null;

    const mods_base_paddr = PAddr.fromInt(info.mods_addr);
    const mods_base_vaddr = VAddr.fromPAddr(mods_base_paddr, .kernel);
    const mods = mods_base_vaddr.getPtr([*]align(1) const Mod);

    var fallback_slice: ?[]const u8 = null;

    var i: u64 = 0;
    while (i < info.mods_count) : (i += 1) {
        const m = mods[i];
        const start_paddr = PAddr.fromInt(m.start);
        const end_paddr = PAddr.fromInt(m.end);
        const start_vaddr = VAddr.fromPAddr(start_paddr, .kernel);
        const end_vaddr = VAddr.fromPAddr(end_paddr, .kernel);
        if (end_vaddr.addr <= start_vaddr.addr) continue;

        const bytes: []const u8 = @as([*]const u8, @ptrFromInt(start_vaddr.addr))[0 .. end_vaddr.addr - start_vaddr.addr];

        // Check explicit name match first
        var name: []const u8 = "";
        if (m.cmdline != 0) {
            const cstr_paddr = PAddr.fromInt(m.cmdline);
            const cstr_vaddr = VAddr.fromPAddr(cstr_paddr, .kernel);
            const cstr = cstr_vaddr.getPtr([*:0]const u8);
            name = std.mem.span(cstr);
            if (name.len != 0 and (std.mem.eql(u8, name, wanted) or std.mem.endsWith(u8, name, wanted))) {
                return bytes;
            }
        }

        // Heuristic: detect symbol map style ("HEX SPACE NAME\n")
        var j: u64 = 0;
        var saw_hex = false;
        while (j < bytes.len and bytes[j] != '\n') : (j += 1) {
            const c = bytes[j];
            if (!saw_hex) {
                if ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')) {
                    saw_hex = true;
                    continue;
                }
                break;
            } else if (c == ' ') {
                var k = j + 1;
                while (k < bytes.len and bytes[k] != '\n' and bytes[k] == ' ') : (k += 1) {}
                if (k < bytes.len and bytes[k] != '\n') {
                    if (fallback_slice == null) fallback_slice = bytes;
                }
                break;
            }
        }

        // If only one module exists, use it as a fallback
        if (info.mods_count == 1 and fallback_slice == null) {
            fallback_slice = bytes;
        }
    }

    return fallback_slice;
}
