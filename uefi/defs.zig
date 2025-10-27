const std = @import("std");
const mmap = @import("mmap.zig");

const uefi = std.os.uefi;

pub const BootInfo = extern struct {
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

pub const MMapEntryType = enum {
    free,
    reserved,
};

pub const MAX_MMAP_ENTRIES = 256;

pub fn collapseMmap(
    map: *const mmap.MMap,
    mmap_entries: *[MAX_MMAP_ENTRIES]MMapEntry,
) []MMapEntry {
    var descriptor: *uefi.tables.MemoryDescriptor = @ptrCast(map.mmap);
    var idx: u64 = 0;

    mmap_entries[idx].start_paddr = descriptor.physical_start;
    mmap_entries[idx].num_pages = descriptor.number_of_pages;
    mmap_entries[idx].type = switch (descriptor.type) {
        .conventional_memory,
        .loader_code,
        .loader_data,
        .boot_services_code,
        .boot_services_data,
        => .free,
        else => .reserved,
    };

    for (1..map.num_descriptors) |i| {
        descriptor = @ptrFromInt(i * map.descriptor_size + @intFromPtr(map.mmap));
        const t: MMapEntryType = switch (descriptor.type) {
            .conventional_memory,
            .loader_code,
            .loader_data,
            .boot_services_code,
            .boot_services_data,
            => .free,
            else => .reserved,
        };

        const same_type = (t == mmap_entries[idx].type);
        const prev_end = mmap_entries[idx].start_paddr + mmap_entries[idx].num_pages * 4096;
        const contiguous = (descriptor.physical_start == prev_end);

        if (same_type and contiguous) {
            mmap_entries[idx].num_pages += descriptor.number_of_pages;
            continue;
        }

        idx += 1;
        std.debug.assert(idx < 256);

        mmap_entries[idx].start_paddr = descriptor.physical_start;
        mmap_entries[idx].num_pages = descriptor.number_of_pages;
        mmap_entries[idx].type = t;
    }

    idx += 1;
    std.debug.assert(idx < 256);

    return mmap_entries[0..idx];
}
