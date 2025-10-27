const std = @import("std");
const uefi = std.os.uefi;

const log = std.log.scoped(.mmap);

pub const MMap = extern struct {
    key: uefi.tables.MemoryMapKey,
    mmap: [*]uefi.tables.MemoryDescriptor,
    mmap_size: u64,
    descriptor_size: u64,
    num_descriptors: u64,
};

pub fn getMmap(
    boot_services: *uefi.tables.BootServices,
) ?MMap {
    var mmap_size: u64 = 0;
    var mmap: ?[*]uefi.tables.MemoryDescriptor = null;
    var key: uefi.tables.MemoryMapKey = undefined;
    var descriptor_size: u64 = undefined;
    var descriptor_version: u32 = undefined;

    var status = boot_services._getMemoryMap(
        &mmap_size,
        null,
        &key,
        &descriptor_size,
        &descriptor_version,
    );
    switch (status) {
        .buffer_too_small => log.debug("Need {d} bytes for mmap", .{
            mmap_size,
        }),
        else => {
            log.err("Expected buffer_too_small but got {s}", .{
                @tagName(status),
            });
            return null;
        },
    }

    // account for the buffer allocation changing the map
    mmap_size += 2 * descriptor_size;

    status = boot_services._allocatePool(
        .loader_data,
        mmap_size,
        @ptrCast(&mmap),
    );
    switch (status) {
        .success => log.debug("Allocated {d} bytes for memory map at 0x{X}", .{
            mmap_size,
            @intFromPtr(mmap.?),
        }),
        else => {
            log.err("Expected success from allocatePool but got {s}", .{
                @tagName(status),
            });
            return null;
        },
    }

    status = boot_services._getMemoryMap(
        &mmap_size,
        @ptrCast(mmap),
        &key,
        &descriptor_size,
        &descriptor_version,
    );
    switch (status) {
        .success => return MMap{
            .key = key,
            .mmap = mmap.?,
            .mmap_size = mmap_size,
            .descriptor_size = descriptor_size,
            .num_descriptors = @divExact(mmap_size, descriptor_size),
        },
        else => {
            log.err("Expected success from getMemoryMap but got {s}", .{
                @tagName(status),
            });
            return null;
        },
    }
}
