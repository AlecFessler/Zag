const zag = @import("zag");

const memory_init = zag.memory.init;

const VAddr = zag.memory.address.VAddr;

pub const VAddrRange = struct {
    vaddr: VAddr,
    size: u64,
};

pub const RestartContext = struct {
    entry_point: VAddr,
    data_segment: struct {
        vaddr: VAddr,
        size: u64,
        ghost: []u8,
    },
    code_range: VAddrRange,
    rodata_range: VAddrRange,
    perm_view_range: VAddrRange,
};

pub fn create(
    entry: VAddr,
    code_range: VAddrRange,
    rodata_range: VAddrRange,
    data_vaddr: VAddr,
    data_content: []const u8,
    perm_view_range: VAddrRange,
) !*RestartContext {
    const rc = try memory_init.heap_allocator.create(RestartContext);
    errdefer memory_init.heap_allocator.destroy(rc);

    const ghost: []u8 = if (data_content.len > 0)
        try memory_init.heap_allocator.dupe(u8, data_content)
    else
        &.{};

    rc.* = .{
        .entry_point = entry,
        .data_segment = .{
            .vaddr = data_vaddr,
            .size = data_content.len,
            .ghost = ghost,
        },
        .code_range = code_range,
        .rodata_range = rodata_range,
        .perm_view_range = perm_view_range,
    };
    return rc;
}

pub fn destroy(rc: *RestartContext) void {
    if (rc.data_segment.ghost.len > 0) {
        memory_init.heap_allocator.free(rc.data_segment.ghost);
    }
    memory_init.heap_allocator.destroy(rc);
}
