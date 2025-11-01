const mmap = @import("mmap.zig");
const std = @import("std");

const ConfigurationTable = uefi.tables.ConfigurationTable;
const Guid = uefi.Guid;
const SystemTable = uefi.tables.SystemTable;
const uefi = std.os.uefi;

pub const MMapEntryType = enum {
    acpi,
    free,
    reserved,
};

pub const BootInfo = extern struct {
    xsdp_paddr: u64,
    mmap: mmap.MMap,
    ksyms: extern struct {
        ptr: [*]const u8,
        len: u64,
    },
};

pub const MMapEntry = struct {
    start_paddr: u64,
    num_pages: u64,
    type: MMapEntryType,
};

pub const MAX_MMAP_ENTRIES = 256;

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

fn guidEq(a: Guid, b: Guid) bool {
    return a.time_low == b.time_low and a.time_mid == b.time_mid and a.time_high_and_version == b.time_high_and_version and a.clock_seq_high_and_reserved == b.clock_seq_high_and_reserved and a.clock_seq_low == b.clock_seq_low and std.mem.eql(
        u8,
        &a.node,
        &b.node,
    );
}
