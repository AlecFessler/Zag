const std = @import("std");
const zag = @import("zag");
const Range = zag.utils.range.Range;
const SpinLock = zag.sched.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;

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
    lock: SpinLock = .{},

    pub fn init(start_vaddr: VAddr, end_vaddr: VAddr) VirtualMemoryManager {
        std.debug.assert(end_vaddr.addr > start_vaddr.addr);
        return .{
            .start_vaddr = start_vaddr,
            .end_vaddr = end_vaddr,
            .free_vaddr = start_vaddr,
        };
    }

    // Called within the page fault handler, so must use irqsave variant of the spinlock
    pub fn isValidVAddr(self: *VirtualMemoryManager, vaddr: VAddr) bool {
        const irq = self.lock.lockIrqSave();
        defer self.lock.unlockIrqRestore(irq);

        for (self.vmm_allocations[0..self.vmm_allocations_idx]) |alloc| {
            const range = Range{
                .start = alloc.vaddr.addr,
                .end = alloc.vaddr.addr + alloc.size,
            };
            if (range.contains(vaddr.addr)) return true;
        }
        return false;
    }

    /// Not ever called within interrupt/exception handlers, but must use irqsave because the page
    /// fault handler calls isValidVAddr on the same lock.
    pub fn reserve(self: *VirtualMemoryManager, size: u64, alignment: std.mem.Alignment) !VAddr {
        const irq = self.lock.lockIrqSave();
        defer self.lock.unlockIrqRestore(irq);

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
