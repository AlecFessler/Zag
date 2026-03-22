const std = @import("std");
const zag = @import("zag");

const memory_init = zag.memory.init;
const paging = zag.memory.paging;

const VAddr = zag.memory.address.VAddr;

pub const RestartContext = struct {
    code: []u8,
    entry: VAddr,
};

pub fn create(binary: []const u8, entry: VAddr) !*RestartContext {
    const rc = try memory_init.heap_allocator.create(RestartContext);
    errdefer memory_init.heap_allocator.destroy(rc);

    const code_copy = try memory_init.heap_allocator.dupe(u8, binary);
    rc.* = .{ .code = code_copy, .entry = entry };
    return rc;
}

pub fn destroy(rc: *RestartContext) void {
    memory_init.heap_allocator.free(rc.code);
    memory_init.heap_allocator.destroy(rc);
}
