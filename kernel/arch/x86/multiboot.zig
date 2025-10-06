//! Multiboot v1 definitions and utilities for `x86_64` kernels.
//!
//! This module provides definitions for working with bootloader-provided information
//! in accordance with the Multiboot Specification v1, specifically targeting the `x86_64`
//! architecture. It includes structures for parsing bootloader metadata, enumerating
//! memory regions, and classifying memory types.
//!
//! This is typically used during early kernel initialization to inspect the memory map
//! and retrieve configuration data provided by the bootloader.

const std = @import("std");

const paging = @import("paging.zig");

pub const MAGIC = 0x2BADB002;
pub const MAX_REGIONS = 32;

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

pub fn checkFlag(flags: u32, bit: u5) bool {
    return 1 == (1 & (flags >> bit));
}

pub const Mod = packed struct {
    start: u32,
    end: u32,
    cmdline: u32,
    padding: u32,
};

pub const ElfSectionHeaderTable = packed struct {
    num: u32,
    size: u32,
    addr: u32,
    shndx: u32,
};

/// Represents a single entry in the memory map provided by a Multiboot v1-compliant bootloader.
/// These entries are found at the physical address given by `mmap_addr` in the `MultibootInfo`
/// struct, and the full memory map spans `mmap_len` bytes. The memory map may be unaligned based
/// on what Zig expects, but it is still valid.
///
/// Each entry describes a contiguous region of physical memory, including its starting address,
/// length in bytes, and usage type.
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

pub fn parseMemoryMap(info: *const MultibootInfo, regions: *[MAX_REGIONS]MemoryRegion) []MemoryRegion {
    var mmap_ptr: u64 = paging.physToVirt(info.mmap_addr);
    const mmap_end: u64 = mmap_ptr + info.mmap_len;
    var i: usize = 0;
    while (mmap_ptr < mmap_end) : (i += 1) {
        // Align to 1 byte because Multiboot v1 does not guarantee alignment of mmap entries.
        const entry: *align(1) const MultibootMmapEntry = @ptrFromInt(mmap_ptr);
        regions[i] = .{
            .addr = entry.addr,
            .len = entry.len,
            .region_type = @enumFromInt(entry.type - 1),
        };
        mmap_ptr += entry.size + @sizeOf(u32);
    }
    return regions[0..i];
}

pub fn parseModules(info: *const MultibootInfo, wanted: []const u8) ?[]const u8 {

    // Bit 3 => mods_count/mods_addr valid
    if (!checkFlag(info.flags, 3) or info.mods_count == 0) return null;

    const mods_base_v: usize = paging.physToVirt(info.mods_addr);
    const mods: [*]align(1) const Mod = @ptrFromInt(mods_base_v);

    var fallback_slice: ?[]const u8 = null;

    var i: usize = 0;
    while (i < info.mods_count) : (i += 1) {
        const m = mods[i];

        // Build [start,end) slice in *virtual* address space
        const start_v: usize = paging.physToVirt(m.start);
        const end_v: usize = paging.physToVirt(m.end); // end is exclusive per spec
        if (end_v <= start_v) continue; // skip nonsense

        const bytes: []const u8 = @as([*]const u8, @ptrFromInt(start_v))[0 .. end_v - start_v];

        // 1) Prefer explicit name match if present (GRUB only sets this if you passed args)
        var name: []const u8 = "";
        if (m.cmdline != 0) {
            const cstr: [*:0]const u8 = @ptrFromInt(paging.physToVirt(m.cmdline));
            name = std.mem.span(cstr);
            if (name.len != 0 and (std.mem.eql(u8, name, wanted) or std.mem.endsWith(u8, name, wanted))) {
                return bytes;
            }
        }

        // 2) Heuristic: does this buffer look like our symbol map? (e.g., "HEX SPACE NAME\n")
        //    Check the first line only to avoid scanning big buffers.
        //    Accept if: some hex digits, then space, then at least one non-space before '\n'.
        var j: usize = 0;
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
