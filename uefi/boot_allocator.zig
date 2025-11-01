const std = @import("std");

const uefi = std.os.uefi;

pub const PageAllocator = struct {
    boot: *uefi.tables.BootServices,
    mem_type: uefi.tables.MemoryType,

    pub fn init(
        boot: *uefi.tables.BootServices,
        mem_type: uefi.tables.MemoryType,
    ) PageAllocator {
        return .{
            .boot = boot,
            .mem_type = mem_type,
        };
    }

    pub fn allocator(self: *PageAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: u64,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *PageAllocator = @alignCast(@ptrCast(ptr));
        std.debug.assert(len == 4096);
        std.debug.assert(alignment.toByteUnits() == 4096);
        const pages = self.boot.allocatePages(
            .any,
            self.mem_type,
            1,
        ) catch return null;
        const page: *[4096]u8 = &pages[0];
        return @ptrCast(page);
    }

    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) void {
        _ = ptr;
        _ = buf;
        _ = alignment;
        _ = ret_addr;
        unreachable;
    }
};
