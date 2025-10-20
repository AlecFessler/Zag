const std = @import("std");

const uefi = std.os.uefi;

pub const BootInfo = extern struct {
    mmap: MemoryMap,
    ksyms: extern struct {
        ptr: [*]const u8,
        len: u64,
    },
};

pub const MemoryMap = extern struct {
    buffer_size: u64,
    descriptors: [*]uefi.tables.MemoryDescriptor,
    map_size: u64,
    map_key: uefi.tables.MemoryMapKey,
    descriptor_size: u64,
    descriptor_version: u32,
};

pub const MemoryDescriptorIterator = struct {
    const Self = @This();

    descriptors: [*]uefi.tables.MemoryDescriptor,
    current: *uefi.tables.MemoryDescriptor,
    descriptor_size: u64,
    total_size: u64,

    pub fn new(map: MemoryMap) Self {
        return Self{
            .descriptors = map.descriptors,
            .current = @ptrCast(map.descriptors),
            .descriptor_size = map.descriptor_size,
            .total_size = map.map_size,
        };
    }

    pub fn next(self: *Self) ?*uefi.tables.MemoryDescriptor {
        if (@intFromPtr(self.current) >= @intFromPtr(self.descriptors) + self.total_size) {
            return null;
        }
        const md = self.current;
        self.current = @ptrFromInt(@intFromPtr(self.current) + self.descriptor_size);
        return md;
    }
};
