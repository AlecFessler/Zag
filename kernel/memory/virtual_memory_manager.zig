const std = @import("std");

/// Global kernel vmm primarily for use by page fault handler and initializing allocators
pub var global_vmm: ?VirtualMemoryManager = null;

/// With the way allocators are planned to be used, there will be very few allocations made
/// from the VMM itself, typically made upfront when allocators are initialized. Because of this,
/// we just use a fixed size array of base + size fat pointers for simplicity and for the page fault
/// handler to quickly check if a faulting address is valid
const MAX_ALLOCATIONS = 16;

pub const VmmAllocation = struct {
    vaddr: u64,
    size: u64,
};

/// Delegating allocator. Requires a backing allocator, can also act as a backing allocator.
pub const VirtualMemoryManager = struct {
    backing_allocator: std.mem.Allocator,
    vmm_allocations: [MAX_ALLOCATIONS]VmmAllocation = undefined,
    vmm_allocations_idx: u32 = 0,

    pub fn init(backing_allocator: std.mem.Allocator) VirtualMemoryManager {
        return .{
            .backing_allocator = backing_allocator,
        };
    }

    pub fn isValidVaddr(self: *VirtualMemoryManager, vaddr: u64) bool {
        for (0..self.vmm_allocations_idx) |i| {
            const range_start = self.vmm_allocations[i].vaddr;
            const range_end = range_start + self.vmm_allocations[i].size;
            const gte_start = vaddr >= range_start;
            const lt_end = vaddr < range_end;
            if (gte_start and lt_end) return true;
        }
        return false;
    }

    pub fn allocator(self: *VirtualMemoryManager) std.mem.Allocator {
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
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *VirtualMemoryManager = @alignCast(@ptrCast(ptr));
        const maybe_vaddr = self.backing_allocator.rawAlloc(
            len,
            alignment,
            ret_addr,
        );
        if (maybe_vaddr) |vaddr| {
            const idx = self.vmm_allocations_idx;
            self.vmm_allocations[idx].vaddr = @intFromPtr(vaddr);
            self.vmm_allocations[idx].size = len;
            self.vmm_allocations_idx += 1;
        }
        return maybe_vaddr;
    }

    // no op
    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    // no op
    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
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
        ret_addr: usize,
    ) void {
        const self: *VirtualMemoryManager = @alignCast(@ptrCast(ptr));
        self.backing_allocator.rawFree(
            buf,
            alignment,
            ret_addr,
        );
    }
};
