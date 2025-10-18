const std = @import("std");
const x86 = @import("x86");

const paging = x86.Paging;

const VAddr = paging.VAddr;

pub const VmmErrors = error{
    TooManyReservations,
    OutOfAddressSpace,
    InvalidSize,
};

pub const VmmAllocation = struct {
    vaddr: VAddr,
    size: u64,
};

pub const VirtualMemoryManager = struct {
    start_vaddr: VAddr,
    end_vaddr: VAddr,
    free_vaddr: VAddr,

    vmm_allocations: [MAX_RESERVATIONS]VmmAllocation = undefined,
    vmm_allocations_idx: u32 = 0,

    pub fn init(start_vaddr: VAddr, end_vaddr: VAddr) VirtualMemoryManager {
        std.debug.assert(end_vaddr.addr > start_vaddr.addr);
        return .{
            .start_vaddr = start_vaddr,
            .end_vaddr = end_vaddr,
            .free_vaddr = start_vaddr,
        };
    }

    pub fn isValidVaddr(self: *VirtualMemoryManager, vaddr: VAddr) bool {
        var i: u32 = 0;
        while (i < self.vmm_allocations_idx) : (i += 1) {
            const base = self.vmm_allocations[i].vaddr;
            const end = VAddr.fromInt(base.addr + self.vmm_allocations[i].size);
            if (vaddr.addr >= base.addr and vaddr.addr < end.addr) return true;
        }
        return false;
    }

    pub fn reserve(self: *VirtualMemoryManager, size: u64, alignment: std.mem.Alignment) !VAddr {
        if (self.vmm_allocations_idx >= MAX_RESERVATIONS) return error.TooManyReservations;
        if (size == 0) return error.InvalidSize;

        const align_bytes: u64 = alignment.toByteUnits();
        const aligned = VAddr.fromInt(std.mem.alignForward(
            u64,
            self.free_vaddr.addr,
            align_bytes,
        ));
        const next = VAddr.fromInt(aligned.addr + size);
        if (next.addr > self.end_vaddr.addr) return error.OutOfAddressSpace;

        self.vmm_allocations[self.vmm_allocations_idx] = .{
            .vaddr = aligned,
            .size = size,
        };
        self.vmm_allocations_idx += 1;

        self.free_vaddr = next;
        return aligned;
    }
};

const MAX_RESERVATIONS = 16;

pub var global_vmm: ?VirtualMemoryManager = null;
