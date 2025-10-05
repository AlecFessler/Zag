const std = @import("std");

/// Global kernel vmm primarily for use by page fault handler and initializing allocators
pub var global_vmm: ?VirtualMemoryManager = null;

/// With the way allocators are planned to be used, there will be very few allocations made
/// from the VMM itself, typically made upfront when allocators are initialized. Because of this,
/// we just use a fixed size array of base + size fat pointers for simplicity and for the page fault
/// handler to quickly check if a faulting address is valid
const MAX_RESERVATIONS = 16;

pub const VmmAllocation = struct {
    vaddr: u64,
    size: u64,
};

pub const VmmErrors = error{
    TooManyReservations,
    OutOfAddressSpace,
    InvalidSize,
};

pub const VirtualMemoryManager = struct {
    start_vaddr: u64,
    end_vaddr: u64,
    free_vaddr: u64,

    vmm_allocations: [MAX_RESERVATIONS]VmmAllocation = undefined,
    vmm_allocations_idx: u32 = 0,

    pub fn init(start_vaddr: u64, end_vaddr: u64) VirtualMemoryManager {
        std.debug.assert(end_vaddr > start_vaddr);
        return .{
            .start_vaddr = start_vaddr,
            .end_vaddr = end_vaddr,
            .free_vaddr = start_vaddr,
        };
    }

    pub fn isValidVaddr(self: *VirtualMemoryManager, vaddr: u64) bool {
        var i: u32 = 0;
        while (i < self.vmm_allocations_idx) : (i += 1) {
            const base = self.vmm_allocations[i].vaddr;
            const end = base + self.vmm_allocations[i].size;
            if (vaddr >= base and vaddr < end) return true;
        }
        return false;
    }

    pub fn reserve(self: *VirtualMemoryManager, size: u64, alignment: std.mem.Alignment) !u64 {
        if (self.vmm_allocations_idx >= MAX_RESERVATIONS) return error.TooManyReservations;
        if (size == 0) return error.InvalidSize;

        const align_bytes: u64 = alignment.toByteUnits();
        const aligned = std.mem.alignForward(u64, self.free_vaddr, align_bytes);
        const next = aligned + size;
        if (next > self.end_vaddr) return error.OutOfAddressSpace;

        self.vmm_allocations[self.vmm_allocations_idx] = .{
            .vaddr = aligned,
            .size = size,
        };
        self.vmm_allocations_idx += 1;

        self.free_vaddr = next;
        return aligned;
    }
};
