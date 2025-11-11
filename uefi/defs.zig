//! Shared boot protocol for Zag: loader↔kernel interface and memory map shaping.
//!
//! Provides the structs and helpers passed from the UEFI loader to the kernel,
//! including a compacted memory map. `collapseMmap` coalesces adjacent UEFI
//! descriptors into simple categories (`free`, `acpi`, `reserved`) to guide
//! early mapping decisions and seed the buddy allocator with usable physmem.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `MMapEntryType` — simplified memory class used post-compaction.
//! - `BootInfo` — payload handed from loader to kernel (XSDP, mmap, ksyms).
//! - `MMapEntry` — one compacted memory-map run (base, pages, type).
//!
//! ## Constants
//! - `MAX_MMAP_ENTRIES` — upper bound on compacted entries produced.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `bootproto.collapseMmap` — compact and coalesce the UEFI memory map.
//! - `bootproto.findXSDP` — locate ACPI 2.0+ RSDP (XSDP) via UEFI system table.
//! - `bootproto.guidEq` — compare two GUIDs for exact equality.

const builtin = @import("builtin");
const mmap = @import("mmap.zig");
const std = @import("std");

const ConfigurationTable = uefi.tables.ConfigurationTable;
const Guid = uefi.Guid;
const SystemTable = uefi.tables.SystemTable;
const uefi = std.os.uefi;

/// Simplified memory classification used by the kernel after compaction.
pub const MMapEntryType = enum {
    acpi,
    free,
    reserved,
};

/// Payload handed off from the loader to the kernel at entry.
pub const BootInfo = extern struct {
    xsdp_paddr: u64,
    mmap: mmap.MMap,
    ksyms: extern struct {
        ptr: [*]const u8,
        len: u64,
    },
};

/// One compacted memory map entry (base address, page count, class).
pub const MMapEntry = struct {
    start_paddr: u64,
    num_pages: u64,
    type: MMapEntryType,
};

/// Maximum number of compacted entries `collapseMmap` will emit.
pub const MAX_MMAP_ENTRIES = 256;

/// Function: `bootproto.collapseMmap`
///
/// Summary:
/// Collapse and coalesce the UEFI memory map into simplified runs of
/// `{acpi, free, reserved}` at 4 KiB granularity, merging adjacent equal-type
/// descriptors into single spans.
///
/// Arguments:
/// - `map`: Pointer to the raw UEFI memory map (`*const mmap.MMap`).
/// - `mmap_entries`: Output buffer with capacity `MAX_MMAP_ENTRIES`.
///
/// Returns:
/// - `[]MMapEntry`: Slice view of the filled prefix in `mmap_entries`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Asserts `map.num_descriptors <= MAX_MMAP_ENTRIES`.
/// - Asserts capacity before emitting a new run.
pub fn collapseMmap(
    map: *const mmap.MMap,
    mmap_entries: *[MAX_MMAP_ENTRIES]MMapEntry,
) []MMapEntry {
    std.debug.assert(map.num_descriptors <= MAX_MMAP_ENTRIES);

    var idx: u64 = 0;
    for (0..map.num_descriptors) |i| {
        const descriptor: *uefi.tables.MemoryDescriptor = @ptrFromInt(i * map.descriptor_size + @intFromPtr(map.mmap));

        const t: MMapEntryType = switch (descriptor.type) {
            .conventional_memory,
            .loader_code,
            .loader_data,
            .boot_services_code,
            .boot_services_data,
            => .free,
            .acpi_reclaim_memory => .acpi,
            else => .reserved,
        };

        if (idx == 0) {
            mmap_entries[0].start_paddr = descriptor.physical_start;
            mmap_entries[0].num_pages = descriptor.number_of_pages;
            mmap_entries[0].type = t;
            idx = 1;
            continue;
        }

        const prev = &mmap_entries[idx - 1];
        const prev_end = prev.start_paddr + prev.num_pages * 4096;

        if (t == prev.type and descriptor.physical_start == prev_end) {
            prev.num_pages += descriptor.number_of_pages;
        } else {
            std.debug.assert(idx < MAX_MMAP_ENTRIES);
            mmap_entries[idx].start_paddr = descriptor.physical_start;
            mmap_entries[idx].num_pages = descriptor.number_of_pages;
            mmap_entries[idx].type = t;
            idx += 1;
        }
    }

    return mmap_entries[0..idx];
}

/// Function: `bootproto.findXSDP`
///
/// Summary:
/// Scan `UEFI SystemTable.ConfigurationTable` for `acpi_20_table_guid` and
/// return the physical address of the ACPI XSDP (RSDP 2.0+).
///
/// Arguments:
/// - None.
///
/// Returns:
/// - `u64`: Physical address of the XSDP on success.
///
/// Errors:
/// - `uefi.Error.Aborted`: No matching configuration table is present.
///
/// Panics:
/// - None.
pub fn findXSDP() !u64 {
    for (0..uefi.system_table.number_of_table_entries) |i| {
        const ct = uefi.system_table.configuration_table[i];
        if (guidEq(
            ct.vendor_guid,
            ConfigurationTable.acpi_20_table_guid,
        )) {
            return @intFromPtr(ct.vendor_table);
        }
    }
    return uefi.Error.Aborted;
}

/// Function: `bootproto.guidEq`
///
/// Summary:
/// Compare two GUIDs for exact field-wise equality.
///
/// Arguments:
/// - `a`: First GUID.
/// - `b`: Second GUID.
///
/// Returns:
/// - `bool`: `true` if all fields are equal; `false` otherwise.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
fn guidEq(a: Guid, b: Guid) bool {
    return a.time_low == b.time_low and a.time_mid == b.time_mid and a.time_high_and_version == b.time_high_and_version and a.clock_seq_high_and_reserved == b.clock_seq_high_and_reserved and a.clock_seq_low == b.clock_seq_low and std.mem.eql(
        u8,
        &a.node,
        &b.node,
    );
}

pub const DwarfSectionId = enum {
    debug_info,
    debug_abbrev,
    debug_str,
    debug_str_offsets,
    debug_line,
    debug_line_str,
    debug_ranges,
    debug_loclists,
    debug_rnglists,
    debug_addr,
    debug_names,
};

pub const Blob = extern struct {
    ptr: u64,
    len: u64,
};

pub const DwarfBootBlobTable = extern struct {
    present_mask: u32,
    blobs: [@intFromEnum(DwarfSectionId.debug_names) + 1]Blob,
};
