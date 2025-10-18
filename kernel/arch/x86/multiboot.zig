//! Multiboot v1 definitions and utilities for `x86_64` kernels.
//!
//! This module provides definitions for working with bootloader-provided information
//! in accordance with the Multiboot Specification v1, specifically targeting the `x86_64`
//! architecture. It includes structures for parsing bootloader metadata, enumerating
//! memory regions, and classifying memory types.
//!
//! This is typically used during early kernel initialization to inspect the memory map
//! and retrieve configuration data provided by the bootloader.

const paging = @import("paging.zig");
const std = @import("std");

const PAddr = paging.PAddr;
const VAddr = paging.VAddr;

/// Represents the type of a physical memory region as described by the Multiboot v1 memory map.
/// These correspond to the values provided in the `type` field of `MultibootMmapEntry`,
/// but note that the parser subtracts 1 so the enum starts at 0 for use as an array index.
///
/// This enum is used to classify memory regions according to their availability or reserved purpose.
pub const MemoryRegionType = enum(u32) {
    /// Usable RAM available for general-purpose allocation.
    Available,

    /// Reserved memory that must not be used by the kernel or applications.
    Reserved,

    /// Reclaimable memory, usable after ACPI tables are parsed.
    AcpiReclaimable,

    /// Non-volatile memory used for sleep states (ACPI NVS), not available for use.
    AcpiNvs,

    /// Memory region containing errors or defects, must not be used.
    BadMem,

    /// Returns a human-readable string representation of the memory region type.
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

/// Represents the Multiboot information structure provided by a compliant bootloader
/// according to the Multiboot Specification v1. This structure is located at the address
/// passed in the `info_ptr` argument to the kernel entry point. It contains a variety of
/// boot-related metadata including memory size, boot device, loaded modules, and more.
/// Fields must be interpreted based on the flags value.
pub const MultibootInfo = packed struct {
    /// Flags indicating which fields are valid.
    flags: u32,

    /// Amount of lower memory (below 1 MB), in kilobytes.
    mem_lower: u32,

    /// Amount of upper memory (above 1 MB), in kilobytes.
    mem_upper: u32,

    /// BIOS boot device the OS was loaded from.
    boot_dev: u32,

    /// Physical address of the kernel command line string.
    cmdline: u32,

    /// Number of modules loaded alongside the kernel.
    mods_count: u32,

    /// Physical address of the first module structure.
    mods_addr: u32,

    /// Elf section header data.
    elf_sections: ElfSectionHeaderTable,

    /// Size of the memory map provided by the bootloader.
    mmap_len: u32,

    /// Physical address of the memory map entries.
    mmap_addr: u32,

    /// Size of the BIOS drive info buffer.
    drives_len: u32,

    /// Physical address of the BIOS drive info buffer.
    drives_addr: u32,

    /// Physical address of the ROM configuration table.
    config_table: u32,

    /// Physical address of a null-terminated string naming the bootloader.
    boot_loader: u32,

    /// Physical address of the APM (Advanced Power Management) table.
    apm_table: u32,

    /// Physical address of the VBE control information.
    vbe_ctl_info: u32,

    /// Physical address of the VBE mode information.
    vbe_mode_info: u32,

    /// Current VBE mode.
    vbe_mode: u16,

    /// VBE interface segment.
    vbe_interface_seg: u16,

    /// VBE interface offset.
    vbe_interface_off: u16,

    /// Length of the VBE interface.
    vbe_interface_len: u16,
};

/// Represents a physical memory region reported by the bootloader.
///
/// Each region includes a base physical address, a length in bytes,
/// and a classification via `MemoryRegionType` (e.g., Available, Reserved).
pub const MemoryRegion = struct {
    /// Starting physical address of the region.
    addr: u64,

    /// Length of the region in bytes.
    len: u64,

    /// Type of region (e.g., usable, reserved, ACPI reclaimable).
    region_type: MemoryRegionType,
};

pub const Mod = packed struct {
    start: u32,
    end: u32,
    cmdline: u32,
    padding: u32,
};

pub const MultibootMmapEntry = packed struct {
    /// Size of the entry, excluding the `size` field itself.
    size: u32,

    /// Starting physical address of the memory region.
    addr: u64,

    /// Length of the memory region in bytes.
    len: u64,

    /// Type of memory region, where 1 indicates usable memory and higher values indicate reserved
    /// or special-purpose regions. This is offset by 1 when converted to `MemoryRegionType`.
    type: u32,
};

pub const ElfSectionHeaderTable = packed struct {
    num: u32,
    size: u32,
    addr: u32,
    shndx: u32,
};

pub const MAGIC = 0x2BADB002;
pub const MAX_REGIONS = 32;

pub fn checkFlag(flags: u32, bit: u5) bool {
    return 1 == (1 & (flags >> bit));
}

pub fn parseMemoryMap(info: *const MultibootInfo, regions: *[MAX_REGIONS]MemoryRegion) []MemoryRegion {
    const mmap_paddr = PAddr.fromInt(info.mmap_addr);
    var mmap_vaddr = VAddr.fromPAddr(mmap_paddr, .kernel);
    const mmap_end_vaddr: VAddr = VAddr.fromInt(mmap_vaddr.addr + info.mmap_len);
    var i: u64 = 0;
    while (mmap_vaddr.addr < mmap_end_vaddr.addr) : (i += 1) {
        // Align to 1 byte because Multiboot v1 does not guarantee alignment of mmap entries.
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

pub fn parseModules(info: *const MultibootInfo, wanted: []const u8) ?[]const u8 {
    // Bit 3 => mods_count/mods_addr valid
    if (!checkFlag(info.flags, 3) or info.mods_count == 0) return null;

    const mods_base_paddr = PAddr.fromInt(info.mods_addr);
    const mods_base_vaddr = VAddr.fromPAddr(mods_base_paddr, .kernel);
    const mods = mods_base_vaddr.getPtr([*]align(1) const Mod);

    var fallback_slice: ?[]const u8 = null;

    var i: u64 = 0;
    while (i < info.mods_count) : (i += 1) {
        const m = mods[i];

        // Build [start,end) slice in *virtual* address space
        const start_paddr = PAddr.fromInt(m.start);
        const start_vaddr = VAddr.fromPAddr(start_paddr, .kernel);
        const end_paddr = PAddr.fromInt(m.end);
        const end_vaddr = VAddr.fromPAddr(end_paddr, .kernel);
        if (end_vaddr.addr <= start_vaddr.addr) continue; // skip nonsense

        const bytes: []const u8 = @as([*]const u8, @ptrFromInt(start_vaddr.addr))[0 .. end_vaddr.addr - start_vaddr.addr];

        // 1) Prefer explicit name match if present (GRUB only sets this if you passed args)
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

        // 2) Heuristic: does this buffer look like our symbol map? (e.g., "HEX SPACE NAME\n")
        //    Check the first line only to avoid scanning big buffers.
        //    Accept if: some hex digits, then space, then at least one non-space before '\n'.
        var j: u64 = 0;
        var saw_hex = false;
        while (j < bytes.len and bytes[j] != '\n') : (j += 1) {
            const c = bytes[j];
            if (!saw_hex) {
                if ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')) {
                    saw_hex = true;
                    continue;
                }
                // if first non-newline char isn't hex, bail on heuristic
                break;
            } else {
                // once we hit a space, ensure at least one non-space follows before newline
                if (c == ' ') {
                    // peek one char ahead for a non-space until newline
                    var k = j + 1;
                    while (k < bytes.len and bytes[k] != '\n' and bytes[k] == ' ') : (k += 1) {}
                    if (k < bytes.len and bytes[k] != '\n') {
                        // looks like "HEX  NAME"
                        if (fallback_slice == null) fallback_slice = bytes;
                    }
                    break;
                }
                // keep consuming hex or other chars; we only care about the first space transition
            }
        }

        // 3) If there is only one module, take it as a fallback last
        if (info.mods_count == 1) {
            if (fallback_slice == null) fallback_slice = bytes;
        }
    }

    return fallback_slice;
}
