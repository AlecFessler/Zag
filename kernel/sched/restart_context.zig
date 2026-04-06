const zag = @import("zag");

const memory_init = zag.memory.init;

const VAddr = zag.memory.address.VAddr;

pub const RestartContext = struct {
    entry_point: VAddr,
    data_segment: struct {
        vaddr: VAddr,
        size: u64,
        ghost: []u8,
    },
};

pub fn create(
    entry: VAddr,
    data_vaddr: VAddr,
    data_ghost: []u8,
) !*RestartContext {
    const rc = try memory_init.heap_allocator.create(RestartContext);

    rc.* = .{
        .entry_point = entry,
        .data_segment = .{
            .vaddr = data_vaddr,
            .size = data_ghost.len,
            .ghost = data_ghost,
        },
    };
    return rc;
}

pub fn destroy(rc: *RestartContext) void {
    if (rc.data_segment.ghost.len > 0) {
        memory_init.heap_allocator.free(rc.data_segment.ghost);
    }
    memory_init.heap_allocator.destroy(rc);
}
